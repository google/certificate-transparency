#!/usr/bin/env python

import io
import multiprocessing
import struct
import sys

import gflags

from ct.client import log_client
from ct.crypto import cert
from ct.crypto import error
from ct.proto import client_pb2

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
def read_cert(tls_buffer):
    cert_length_prefix = tls_buffer.read(3)
    if len(cert_length_prefix) != 3:
        raise Error("Input too short")
    cert_length, = struct.unpack(">I", '\x00' + cert_length_prefix)

    cert = tls_buffer.read(cert_length)
    if len(cert) < cert_length:
        raise Error("Input too short")
    return cert


def read_extensions(tls_buffer):
    extensions_length_prefix = tls_buffer.read(2)
    if len(extensions_length_prefix) != 2:
        raise Error("Input too short: expected a 2-byte extension length "
                    "prefix, read %d bytes" % extensions_length_prefix)
    extensions_length, = struct.unpack(">H", extensions_length_prefix)

    extensions = tls_buffer.read(extensions_length)
    if len(extensions) != extensions_length:
        raise Error("Input too short: expected extensions of length %d, "
                    "read %d bytes" %
                    (extensions_length, len(extensions)))
    return extensions


def decode_entry(serialized_entry):
    entry = client_pb2.EntryResponse()
    entry.ParseFromString(serialized_entry)
    leaf_bytes = io.BytesIO(entry.leaf_input)

    version = leaf_bytes.read(1)
    if not version:
        raise Error("Input too short")
    version, = struct.unpack(">B", version)
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

    if entry_type == X509_ENTRY:
        cert = read_cert(leaf_bytes)
        read_extensions(leaf_bytes)

        if leaf_bytes.read():
            raise Error("Input too long")

    else:
        # Precert entry: extract the full precertificate from extra_data.
        # This currently does just enough to extract the precert, and doesn't
        # verify the rest of the leaf input.
        extra_data = io.BytesIO(entry.extra_data)
        cert = read_cert(extra_data)

    return entry_type, cert

def match(certificate, entry_type):
    # Fill this in with your match criteria, e.g.
    #
    # return "google" in certificate.subject_name().lower()
    #
    # NB: for precertificates, issuer matching may not work as expected
    # when the precertificate has been issued by the special-purpose
    # precertificate signing certificate.
    return True

class QueueMessage(object):
    def __init__(self, msg, wait_for_ack=False):
        self.msg = msg
        # Require user interaction to continue.
        self.wait_for_ack = wait_for_ack

# Special queue messages to stop the subprocesses.
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
            # der_cert is either the certificate or the precertificate.
            entry_type, der_cert = decode_entry(entry)
            c = None
            try:
                c = cert.Certificate(der_cert)
            except error.Error as e:
                try:
                    c = cert.Certificate(der_cert, strict_der=False)
                except error.Error as e:
                    output_queue.put(QueueMessage(
                        "Error while parsing entry no %d:\n%s" %
                        (count, e), wait_for_ack=True))
                else:
                    output_queue.put(QueueMessage(
                        "Entry no %d failed strict parsing:\n%s" %
                        (count, c), wait_for_ack=False))
            if c and match(c, entry_type):
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
        # so send serialized entry.
        entry_queue.put((scanned, entry.SerializeToString()))
    # Scanner done; signal workers from the same process.
    # From http://docs.python.org/2/library/multiprocessing.html :
    # If multiple processes are enqueuing objects, it is possible for the
    # objects to be received at the other end out-of-order. However, objects
    # enqueued by the same process will always be in the expected order with
    # respect to each other.
    for _ in range(FLAGS.multi):
        entry_queue.put((0, STOP_WORKER))

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
            if msg.msg == WORKER_STOPPED:
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
