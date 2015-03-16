import abc
import gflags
import hashlib
import logging
import multiprocessing
import sys
import threading
import traceback

from ct.cert_analysis import all_checks
from ct.cert_analysis import asn1
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


class PoolException(Exception):
    def __init__(self, fail_info):
        super(PoolException, self).__init__("One of threads in pool encountered"
                                            " an exception")
        self.failure = fail_info

def _scan_der_cert(der_certs, checks):
    current = -1
    try:
        result = []
        for log_index, der_cert, der_chain in der_certs:
            current = log_index
            partial_result = []
            strict_failure = False
            try:
                certificate = cert.Certificate(der_cert)
            except error.Error as e:
                try:
                    certificate = cert.Certificate(der_cert, strict_der=False)
                except error.Error as e:
                    partial_result.append(asn1.All())
                    strict_failure = True
                else:
                    if isinstance(e, error.ASN1IllegalCharacter):
                        partial_result.append(asn1.Strict(reason=e.args[0],
                                                       details=(e.string, e.index)))
                    else:
                        partial_result.append(asn1.Strict(reason=str(e)))
            if not strict_failure:
                for check in checks:
                    partial_result += check.check(certificate) or []
                desc = cert_desc.from_cert(certificate, partial_result)
            else:
                desc = certificate_pb2.X509Description()
                desc.der = der_cert
                desc.sha256_hash = hashlib.sha256(der_cert).digest()
            try:
                root = cert.Certificate(der_chain[-1], strict_der=False)
            except error.Error:
                pass
            else:
                for iss in [(type_.short_name, cert_desc.to_unicode(
                        '.'.join(cert_desc.process_name(value.human_readable()))))
                            for type_, value in root.issuer()]:
                    proto_iss = desc.root_issuer.add()
                    proto_iss.type, proto_iss.value = iss
            result.append((desc, log_index, partial_result))
        return result
    except Exception:
        _, exception, exception_traceback = sys.exc_info()
        exception_traceback  = traceback.format_exc(exception_traceback)
        raise PoolException((exception, exception_traceback,
                             der_certs[0][0], der_certs[-1][0], current))


class CertificateReport(object):
    """Stores description of new entries between last verified STH and current."""
    __metaclass__ = abc.ABCMeta

    def __init__(self, checks=all_checks.ALL_CHECKS,
                 pool_size=FLAGS.reporter_workers,
                 queue_size=FLAGS.reporter_queue_size):
        self.reset()
        self.checks = checks
        self._jobs = Queue(queue_size)
        self._pool = None
        self._writing_handler = None

    @abc.abstractmethod
    def report(self):
        """Report stored changes and reset report."""
        if self._writing_handler:
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
        """Scans certificates in der form for all supported observations.

        Args:
            der_certs: non empty array of (log_index, der_cert, der_chain) tuples.
        """
        if not self._pool:
            self._pool = multiprocessing.Pool(processes=FLAGS.reporter_workers)
        if not self._writing_handler:
            self._writing_handler = threading.Thread(target=handle_writing,
                                                     args=(self._jobs, self))
            self._writing_handler.start()
        self._jobs.put(self._pool.apply_async(_scan_der_cert,
                                                 [der_certs, self.checks]))


def handle_writing(queue, report):
    while True:
        result = queue.get()
        if result is None:
            queue.task_done()
            break
        try:
            result = result.get()
        except PoolException as e:
            ex, ex_tb, first, last, bad_one = e.failure
            logging.error(ex_tb)
            logging.error(ex.args[0])
            logging.error("Entry %d in batch <%d, %d> %s" % (bad_one,
                          first, last, "raised an exception during scan"))
        else:
            report._batch_scanned_callback(result)
        queue.task_done()
