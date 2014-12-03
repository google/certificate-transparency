import gflags
import logging
import multiprocessing
import sys
import traceback

from collections import defaultdict
from ct.cert_analysis import all_checks
from ct.cert_analysis import asn1
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
            result.append((log_index, partial_result))
        return result
    except:
        _, ex, ex_tb = sys.exc_info()
        ex_tb = traceback.format_exc(ex_tb)
        raise PoolException((ex, ex_tb, der_certs[0][0], der_certs[-1][0]))


class CertificateReport(object):
    """Stores description of new entries between last verified STH and
    current."""

    def __init__(self, checks=all_checks.ALL_CHECKS):
        self.reset()
        self.checks = checks
        self._pool = multiprocessing.Pool(processes=FLAGS.reporter_workers)

    def set_new_entries_count(self, count):
        """Set number of new entries"""
        self._new_entries_count = count

    def report(self):
        """Report stored changes and reset report"""
        for job in self._jobs:
            try:
                job.get()
            except PoolException as e:
                ex, ex_tb, first, last = e.failure
                logging.critical(ex_tb)
                logging.critical(ex.args[0])
                logging.critical("Batch <%d, %d> %s" % (first, last,
                                            "raised an exception during scan"))
        logging.info("Report:")
        if self._new_entries_count:
            logging.info("New entries since last verified STH: %s" %
                         self._new_entries_count)
        logging.info("Number of entries with observations: %d" %
                     len(self._observations_by_index))
        logging.info("Observations:")
        for index, cert_observations in sorted(
                self._observations_by_index.iteritems()):
            msg = "Cert %d:" % index
            observations = []
            for obs in cert_observations:
                observations.append(str(obs))
            if observations:
                logging.info("%s %s", msg, ', '.join(observations))

        stats = defaultdict(int)
        for observations in self._observations_by_index.itervalues():
            # here we care only about description and reason, because details
            # will be probably different for every single observation
            unique_observations = set((obs.description, obs.reason)
                                      for obs in observations)
            for obs in unique_observations:
                stats[obs] += 1
        # if number of new entries is unknown then we just count percentages
        # based on number of certificates with observations
        if not self._new_entries_count:
            self._new_entries_count = len(self._observations_by_index)
        logging.info("Stats:")
        for description_reason, count in stats.iteritems():
            description, reason = description_reason
            logging.info("%s %s: %d (%.5f%%)"
                         % (description,
                            "(%s)" % reason if reason else '',
                            count,
                            float(count) / self._new_entries_count * 100.))
        ret = self._observations_by_index
        self.reset()
        return ret

    def reset(self):
        self._new_entries_count = None
        self._observations_by_index = defaultdict(list)
        self._jobs = []

    def _add_certificate_observations(self, indexed_observations):
        """Adds Observations for certificates identified by indexes
        in logs.

        Args:
            indexed_observations: array of (log_index, observations) tuples.
        """
        for log_index, observations in indexed_observations:
            self._observations_by_index[log_index] += observations

    def scan_der_certs(self, der_certs):
        """Scans certificates in der form for all supported observations.

        Args:
            der_certs: non empty array of (log_index, observations) tuples.
        """
        self._jobs.append(self._pool.apply_async(_scan_der_cert,
                                                 [der_certs, self.checks],
           callback=lambda result: self._add_certificate_observations(result)))
