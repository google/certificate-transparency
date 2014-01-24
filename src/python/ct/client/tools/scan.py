#!/usr/bin/env python

import io
import multiprocessing
import struct
import sys

import gflags

from ct.client import log_client
from ct.client import tls_message
from ct.crypto import cert
from ct.crypto import error
from ct.proto import client_pb2

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("multi", 1, "Number of cert parsing processes to use in "
                      "addition to the main process and the network process.")


def decode_entry(serialized_entry):
    entry = client_pb2.EntryResponse()
    entry.ParseFromString(serialized_entry)
    parsed_entry = client_pb2.ParsedEntry()

    leaf_reader = tls_message.TLSReader(entry.leaf_input)
    leaf_reader.read(parsed_entry.merkle_leaf)

    parsed_entry.extra_data.entry_type = (parsed_entry.merkle_leaf.
                                          timestamped_entry.entry_type)

    extra_data_reader = tls_message.TLSReader(entry.extra_data)
    extra_data_reader.read(parsed_entry.extra_data)

    return parsed_entry

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
            parsed_entry = decode_entry(entry)
            ts_entry = parsed_entry.merkle_leaf.timestamped_entry
            c = None
            if ts_entry.entry_type == client_pb2.X509_ENTRY:
                der_cert = ts_entry.asn1_cert
            else:
                # The original, signed precertificate.
                der_cert = (parsed_entry.extra_data.precert_chain_entry.
                            precertificate_chain[0])
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
            if c and match(c, ts_entry.entry_type):
                output_queue.put(QueueMessage(
                    "Found matching certificate:\n%s" % c,
                    wait_for_ack=True))
            if not count % 1000:
                output_queue.put(QueueMessage("Scanned %d entries" % count))

def scan(entry_queue, output_queue):
    client = log_client.LogClient("ct.googleapis.com/pilot")
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
