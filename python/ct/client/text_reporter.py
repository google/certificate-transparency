import gflags
import logging

from collections import defaultdict
from ct.cert_analysis import all_checks
from ct.client import reporter

FLAGS = gflags.FLAGS

class TextCertificateReport(reporter.CertificateReport):
    """Stores description of new entries between last verified STH and
    current."""

    def __init__(self, checks=all_checks.ALL_CHECKS):
        super(TextCertificateReport, self).__init__(checks=checks)

    def report(self):
        """Report stored changes and reset report."""
        super(TextCertificateReport, self).report()
        logging.info("Report:")
        entries_with_issues = 0
        for obs in self._observations_by_index.values():
            if len(obs):
                entries_with_issues +=1
        new_entries_count = len(self._observations_by_index)
        logging.info("New entries since last verified STH: %s" %
                     new_entries_count)
        logging.info("Number of entries with observations: %d" %
                     entries_with_issues)
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
        logging.info("Stats:")
        for description_reason, count in stats.iteritems():
            description, reason = description_reason
            logging.info("%s %s: %d (%.5f%%)"
                         % (description,
                            "(%s)" % reason if reason else '',
                            count,
                            float(count) / new_entries_count * 100.))
        ret = self._observations_by_index
        self.reset()
        return ret

    def reset(self):
        """Clean up report.

        It's also ran at start."""
        self._observations_by_index = defaultdict(list)

    def _batch_scanned_callback(self, result):
        for desc, log_index, observations in result:
            self._observations_by_index[log_index] += observations
