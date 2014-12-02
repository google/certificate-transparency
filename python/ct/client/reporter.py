import abc
import gflags
import logging
import multiprocessing
import sys
import traceback

from ct.cert_analysis import all_checks
from ct.cert_analysis import asn1
from ct.client.db import cert_desc
from ct.crypto import cert
from ct.crypto import error

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("reporter_workers", multiprocessing.cpu_count(),
                      "Number of subprocesses scanning certificates.")

class PoolException(Exception):
    def __init__(self, fail_info):
        super(PoolException, self).__init__("One of threads in pool encountered"
                                            " an exception")
        self.failure = fail_info

def _scan_der_cert(der_certs, checks):
    try:
        result = []
        for log_index, der_cert in der_certs:
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
                desc = cert_desc.CertificateDescription.from_cert(certificate)
            else:
                desc = cert_desc.CertificateDescription.from_values(der=der_cert)
            result.append((desc, log_index, partial_result))
        return result
    except Exception:
        # TODO(laiqu) return exact certificate index which caused an exception
        # instead of range.
        _, exception, exception_traceback = sys.exc_info()
        exception_traceback  = traceback.format_exc(exception_traceback)
        raise PoolException((exception, exception_traceback,
                             der_certs[0][0], der_certs[-1][0]))


class CertificateReport(object):
    """Stores description of new entries between last verified STH and    current."""
    __metaclass__ = abc.ABCMeta

    def __init__(self, checks=all_checks.ALL_CHECKS,
                 pool_size=FLAGS.reporter_workers):
        self.reset()
        self.checks = checks
        self._jobs = []
        self._pool = None

    @abc.abstractmethod
    def report(self):
        """Report stored changes and reset report."""
        for job in self._jobs:
            try:
                job.get()
            except PoolException as e:
                ex, ex_tb, first, last = e.failure
                logging.critical(ex_tb)
                logging.critical(ex.args[0])
                logging.critical("Batch <%d, %d> %s" % (first, last,
                                            "raised an exception during scan"))

    @abc.abstractmethod
    def _batch_scanned_callback(self, result):
        """Callback called after scanning der_certs passed to scan_der_certs."""

    @abc.abstractmethod
    def reset(self):
        """Clean up report."""
        self._jobs = []

    def scan_der_certs(self, der_certs):
        """Scans certificates in der form for all supported observations.

        Args:
            der_certs: non empty array of (log_index, observations) tuples.
        """
        if not self._pool:
            self._pool = multiprocessing.Pool(processes=FLAGS.reporter_workers)
        self._jobs.append(self._pool.apply_async(_scan_der_cert,
                                                 [der_certs, self.checks],
           callback=lambda result: self._batch_scanned_callback(result)))
