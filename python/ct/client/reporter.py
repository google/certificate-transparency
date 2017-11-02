import abc
import hashlib
import logging
import multiprocessing
import sys
import threading
import traceback

from absl import flags as gflags
from ct.client.db import cert_desc
from ct.crypto import cert
from ct.crypto import error
from ct.proto import certificate_pb2
from Queue import Queue

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("reporter_workers", multiprocessing.cpu_count(),
                      "Number of subprocesses scanning certificates.")

gflags.DEFINE_integer("reporter_queue_size", 50,
                      "Size of entry queue in reporter")


def _scan_der_cert(der_certs):
    current = -1
    result = []
    for log_index, der_cert, der_chain, entry_type in der_certs:
        try:
            current = log_index
            certificate = None
            strict_failure = False
            try:
                certificate = cert.Certificate(der_cert)
            except error.Error as e:
                try:
                    certificate = cert.Certificate(der_cert, strict_der=False)
                except error.Error as e:
                    strict_failure = True
            if not strict_failure:
                desc = cert_desc.from_cert(certificate)
            else:
                desc = certificate_pb2.X509Description()
                desc.der = der_cert
                desc.sha256_hash = hashlib.sha256(der_cert).digest()

            desc.entry_type = entry_type
            root = None

            if der_chain:
                try:
                    issuer = cert.Certificate(der_chain[0], strict_der=False)
                except error.Error:
                    pass
                else:
                    desc.issuer_pk_sha256_hash = issuer.key_hash(hashfunc="sha256")

                try:
                    root = cert.Certificate(der_chain[-1], strict_der=False)
                except error.Error:
                    pass
            else:
                # No chain implies this is a root certificate.
                # Note that certificate may be None.
                root = certificate

            if root:
                for iss in [(type_.short_name, cert_desc.to_unicode(
                        '.'.join(cert_desc.process_name(value.human_readable()))))
                            for type_, value in root.issuer()]:
                    proto_iss = desc.root_issuer.add()
                    proto_iss.type, proto_iss.value = iss

            result.append((desc, log_index))
        except:
            batch_start_index, batch_end_index = (
                    der_certs[0][0], der_certs[-1][0])
            logging.exception(
                    "Error scanning certificate %d in batch <%d, %d> - it will "
                    "be excluded from the scan results",
                    current, batch_start_index, batch_end_index)

    return result


class CertificateReport(object):
    """Stores description of new entries between last verified STH and current."""
    __metaclass__ = abc.ABCMeta

    def __init__(self, queue_size=None):
        self.reset()
        self._jobs = Queue(queue_size or FLAGS.reporter_queue_size)
        self._pool = None
        self._writing_handler = None

    def _writing_handler_ready(self):
        return self._writing_handler and self._writing_handler.is_alive()

    @abc.abstractmethod
    def report(self):
        """Report stored changes and reset report."""
        if self._writing_handler_ready():
            self._jobs.join()
            self._jobs.put(None)
            self._writing_handler.join()
            self._writing_handler = None

    @abc.abstractmethod
    def _batch_scanned_callback(self, result):
        """Callback called after scanning der_certs passed to scan_der_certs."""

    @abc.abstractmethod
    def reset(self):
        """Clean up report."""

    def scan_der_certs(self, der_certs):
        """Scans certificates in der form, parsing them to produce
        X509Description for each.

        Args:
            der_certs: non empty array of
                       (log_index, der_cert, der_chain, entry_type) tuples.
        """
        if not self._pool:
            self._pool = multiprocessing.Pool(processes=FLAGS.reporter_workers)
        if not self._writing_handler_ready():
            self._writing_handler = threading.Thread(target=handle_writing,
                                                     args=(self._jobs, self))
            self._writing_handler.start()
        self._jobs.put(self._pool.apply_async(_scan_der_cert,
                                                 [der_certs]))


def handle_writing(queue, report):
    while True:
        try:
            scan_results = queue.get()
            # This check must be performed in the try block so task_done will
            # be invoked in the finally block regardless of the check results.
            if not scan_results:
                break
            report._batch_scanned_callback(scan_results.get())
        except:
            logging.exception("Error occurred during certificate scanning")
        finally:
            queue.task_done()
