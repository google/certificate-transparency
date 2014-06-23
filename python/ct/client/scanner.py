#!/usr/bin/env python

import collections
import multiprocessing

from ct.client import log_client
from ct.client import tls_message
from ct.crypto import cert
from ct.crypto import error
from ct.proto import client_pb2


def _decode_entry(serialized_entry):
    entry = client_pb2.EntryResponse()
    entry.ParseFromString(serialized_entry)
    parsed_entry = client_pb2.ParsedEntry()

    tls_message.decode(entry.leaf_input, parsed_entry.merkle_leaf)

    parsed_entry.extra_data.entry_type = (parsed_entry.merkle_leaf.
                                          timestamped_entry.entry_type)

    tls_message.decode(entry.extra_data, parsed_entry.extra_data)

    return parsed_entry

# Messages types:
# Special queue messages to stop the subprocesses.
_WORKER_STOPPED = "WORKER_STOPPED"
_ERROR_PARSING_ENTRY = "ERROR_PARSING_ENTRY"
_ENTRY_MATCHING = "ENTRY_MATCHING"
_PROGRESS_REPORT = "PROGRESS_REPORT"


class QueueMessage(object):
    def __init__(self, msg_type, msg=None, certificates_scanned=1):
        self.msg_type = msg_type
        self.msg = msg
        # Number of certificates scanned.
        self.certificates_scanned = certificates_scanned


# This is only used on the entries input queue
_STOP_WORKER = "STOP_WORKER"


def process_entries(entry_queue, output_queue, match_callback):
    stopped = False
    total_processed = 0
    while not stopped:
        count, entry = entry_queue.get()
        if entry == _STOP_WORKER:
            stopped = True
            # Each worker signals when they've picked up their
            # "STOP_WORKER" message.
            output_queue.put(QueueMessage(
                _WORKER_STOPPED,
                certificates_scanned=total_processed))
        else:
            parsed_entry = _decode_entry(entry)
            ts_entry = parsed_entry.merkle_leaf.timestamped_entry
            total_processed += 1
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
                        _ERROR_PARSING_ENTRY,
                        "Error parsing entry %d:\n%s" %
                        (count, e)))
                else:
                    output_queue.put(QueueMessage(
                        _ERROR_PARSING_ENTRY,
                        "Entry %d failed strict parsing:\n%s" %
                        (count, c)))
            if c and match_callback(c, ts_entry.entry_type, count):
                output_queue.put(QueueMessage(
                    _ENTRY_MATCHING,
                    "Entry %d:\n%s" % (count, c)))
            if not count % 1000:
                output_queue.put(QueueMessage(
                    _PROGRESS_REPORT,
                    "Scanned %d entries" % count))

def _scan(entry_queue, output_queue, log_url, num_processes):
    client = log_client.LogClient(log_url)
    sth = client.get_sth()
    output_queue.put(QueueMessage(_PROGRESS_REPORT, "Got STH: %s" % sth))
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
    for _ in range(num_processes):
        entry_queue.put((0, _STOP_WORKER))

ScanResults = collections.namedtuple(
    'ScanResults', ['total', 'matches', 'errors'])

def scan_log(match_callback, log_url, num_processes=1):
    # (index, entry) tuples
    entry_queue = multiprocessing.Queue(10000)
    output_queue = multiprocessing.Queue(10000)

    scan_process = multiprocessing.Process(
        target=_scan,
        args=(entry_queue, output_queue, log_url, num_processes))
    scan_process.start()

    workers = [
        multiprocessing.Process(
            target=process_entries,
            args=(entry_queue, output_queue, match_callback))
               for _ in range(num_processes)]
    for w in workers:
        w.start()

    total_scanned = 0
    total_matches = 0
    total_errors = 0
    try:
        workers_done = 0
        while workers_done < len(workers):
            msg = output_queue.get()
            if msg.msg_type == _WORKER_STOPPED:
                workers_done += 1
                total_scanned += msg.certificates_scanned
            else:
                if msg.msg_type == _ERROR_PARSING_ENTRY:
                    total_errors += 1
                elif msg.msg_type == _ENTRY_MATCHING:
                    total_matches += 1
                else:
                    print msg.msg

    # Do not hang the interpreter upon ^C.
    except (KeyboardInterrupt, SystemExit):
        scan_process.terminate()
        for w in workers:
            w.terminate()
        raise

    scan_process.join()
    for w in workers:
        w.join()
    return ScanResults(
        total_scanned, total_matches, total_errors)
