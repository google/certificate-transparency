#!/usr/bin/env python

import io
import multiprocessing
import struct
import sys

import gflags

from ct.client import log_client
from ct.crypto import cert
from ct.crypto import error

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("multi", 1, "Number of cert parsing processes to use in "
                      "addition to the main process and the network process.")


class Error(Exception):
    pass

# Temporary glue code
# TODO(ekasper): define the constants properly in the decoder.
V1 = 0
TIMESTAMPED_ENTRY = 0
X509_ENTRY, PRECERT_ENTRY = range(2)

# TODO(ekasper): replace with a proper TLS decoder.
def decode_leaf_input(leaf_input):
    leaf_bytes = io.BytesIO(leaf_input)

    version = leaf_bytes.read(1)
    if not version:
        raise Error("Input too short")
    version, = struct.unpack(">B", version)
    # TODO(ekasper): replace with enums
    if version != V1:
        raise Error("Unsupported version %d" % version)

    leaf_type = leaf_bytes.read(1)
    if not leaf_type:
        raise Error("Input too short")
    leaf_type, = struct.unpack(">B", leaf_type)
    if leaf_type != 0:
        raise Error("Unsupported leaf_type %d" % leaf_type)

    timestamp = leaf_bytes.read(8)
    if len(timestamp) < 8:
        raise Error("Input too short")
    timestamp, = struct.unpack(">Q", timestamp)

    entry_type = leaf_bytes.read(2)
    if len(entry_type) < 2:
        raise Error("Input too short")
    entry_type, = struct.unpack(">H", entry_type)
    if entry_type != X509_ENTRY and entry_type != PRECERT_ENTRY:
        raise Error("Unsupported entry_type %d" % entry_type)

    cert_length_prefix = leaf_bytes.read(3)
    if len(cert_length_prefix) != 3:
        raise Error("Input too short")
    cert_length, = struct.unpack(">I", '\x00' + cert_length_prefix)

    cert = leaf_bytes.read(cert_length)
    if len(cert) < cert_length:
        raise Error("Input too short")

    extensions_length_prefix = leaf_bytes.read(2)
    if len(extensions_length_prefix) != 2:
        raise Error("Input too short")
    extensions_length, = struct.unpack(">H", extensions_length_prefix)

    extensions = leaf_bytes.read(extensions_length)
    if len(extensions) != extensions_length:
        raise Error("Input too short")

    if leaf_bytes.read():
        raise Error("Input too long")

    return entry_type, cert

def match(certificate):
    # Fill this in with your match criteria, e.g.
    #
    # return "google" in certificate.subject_name().lower()
    #
    return True

class QueueMessage(object):
    def __init__(self, msg, wait_for_ack=False):
        self.msg = msg
        # Require user interaction to continue.
        self.wait_for_ack = wait_for_ack

# Special queue messages to stop the subprocesses.
SCANNER_STOPPED = "SCANNER_STOPPED"
WORKER_STOPPED = "WORKER_STOPPED"
STOP_WORKER = "STOP_WORKER"

def process_entries(entry_queue, output_queue):
    stopped = False
    while not stopped:
        count, entry = entry_queue.get()
        if entry == STOP_WORKER:
            stopped = True
            # Each worker signals when they've picked up their
            # "STOP_WORKER" message.
            output_queue.put(QueueMessage(WORKER_STOPPED))
        else:
            entry_type, der_cert = decode_leaf_input(entry)
            if entry_type == PRECERT_ENTRY:
                output_queue.put(QueueMessage(
                    "Found precert: %s" % der_cert.encode("hex"),
                    wait_for_ack=True))
            else:
                try:
                    c = cert.Certificate(der_cert)
                except error.Error as e:
                    output_queue.put(QueueMessage(
                        "Error while parsing entry no %d:\n%s" % (scanned, e),
                        wait_for_ack=True))
                else:
                    if match(c):
                        output_queue.put(QueueMessage(
                            "Found matching certificate:\n%s" % c,
                            wait_for_ack=True))
            if not count % 1000:
                output_queue.put(QueueMessage("Scanned %d entries" % count))

def scan(entry_queue, output_queue):
    client = log_client.LogClient(log_client.Requester(
            "ct.googleapis.com/pilot"))
    sth = client.get_sth()
    output_queue.put(QueueMessage("Got STH: %s" % sth))
    # This, too, could be parallelized but currently we're computation-bound
    # due to slow ASN.1 parsing.
    entries = client.get_entries(0, sth.tree_size - 1)
    scanned = 0
    for entry in entries:
        scanned += 1
        # Can't pickle protocol buffers with protobuf module version < 2.5.0
        # (https://code.google.com/p/protobuf/issues/detail?id=418)
        # so we just send the leaf input.
        entry_queue.put((scanned, entry.leaf_input))
    output_queue.put(QueueMessage(SCANNER_STOPPED))

def run():
    # (index, entry) tuples
    entry_queue = multiprocessing.Queue(10000)
    output_queue = multiprocessing.Queue(10000)

    scan_process = multiprocessing.Process(target=scan,
                                           args=(entry_queue, output_queue))
    scan_process.start()

    workers = [multiprocessing.Process(target=process_entries,
                                       args=(entry_queue, output_queue))
               for _ in range(FLAGS.multi)]
    for w in workers:
        w.start()

    try:
        workers_done = 0
        while workers_done < len(workers):
            msg = output_queue.get()
            if msg.msg == SCANNER_STOPPED:
                # Scanner done; signal workers.
                for _ in range(len(workers)):
                    entry_queue.put((0, STOP_WORKER))
            # Worker done.
            elif msg.msg == WORKER_STOPPED:
                workers_done += 1
            else:
                print msg.msg
                if msg.wait_for_ack:
                    raw_input("Press ENTER to continue")

    # Do not hang the interpreter upon ^C.
    except (KeyboardInterrupt, SystemExit):
        scan_process.terminate()
        for w in workers:
            w.terminate()
        raise

    scan_process.join()
    for w in workers:
        w.join()

if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
    run()
