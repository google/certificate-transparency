import gflags
import logging
import multiprocessing

from collections import defaultdict
from ct.cert_analysis import all_checks
from ct.cert_analysis import asn1
from ct.crypto import cert
from ct.crypto import error

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("report_workers", multiprocessing.cpu_count(), "Number of subprocesses scanning "
                      "certificates.")

def _scan_der_cert(der_certs, checks):
    result = []
    for log_index, der_cert in der_certs:
        partial_result = []
        try:
            certificate = cert.Certificate(der_cert)
        except error.Error as e:
            try:
                certificate = cert.Certificate(der_cert, strict_der=False)
            except error.Error as e:
                partial_result.append(asn1.All())
            else:
                if isinstance(e, error.ASN1IllegalCharacter):
                    partial_result.append(asn1.Strict(reason=e.args[0],
                                                   details=(e.string, e.index)))
                else:
                    partial_result.append(asn1.Strict(reason=str(e)))
        else:
            for check in checks:
                partial_result += check.check(certificate) or []
        result.append((log_index, partial_result))
    return result

class CertificateReport(object):
    """Stores description of new entries between last verified STH and
    current."""

    def __init__(self, checks=all_checks.ALL_CHECKS):
        self.reset()
        self.checks = checks

    def set_new_entries_count(self, count):
        """Set number of new entries"""
        self._new_entries_count = count

    def report(self):
        """Report stored changes and reset report"""
        self._pool.close()
        self._pool.join()
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
        self.reset()

    def reset(self):
        self._new_entries_count = None
        self._observations_by_index = defaultdict(list)
        self._pool = multiprocessing.Pool(processes=FLAGS.report_workers)

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
            der_certs: array of (log_index, observations) tuples.
        """
        self._pool.apply_async(_scan_der_cert, [der_certs, self.checks],
           callback=lambda result: self._add_certificate_observations(result))
