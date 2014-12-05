import logging

from collections import defaultdict
from ct.cert_analysis import all_checks
from ct.cert_analysis import asn1
from ct.crypto import cert
from ct.crypto import error

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

    def _add_certificate_observation(self, log_index, observation):
        """Adds Issue for certificate identified by index
        in logs"""
        self._observations_by_index[log_index].append(observation)

    def scan_der_cert(self, log_index, der_cert):
        """Scans certificate in der form for all supported observations"""
        try:
            certificate = cert.Certificate(der_cert)
        except error.Error as e:
            try:
                certificate = cert.Certificate(der_cert, strict_der=False)
            except error.Error as e:
                self._add_certificate_observation(log_index,
                                asn1.All())
                return
            else:
                if isinstance(e, error.ASN1IllegalCharacter):
                    self._add_certificate_observation(log_index,
                     asn1.Strict(reason=e.args[0], details=(e.string, e.index)))
                else:
                    self._add_certificate_observation(log_index,
                            asn1.Strict(reason=str(e)))
        else:
            for check in self.checks:
                for obs in check.check(certificate) or []:
                   self._add_certificate_observation(log_index, obs)
