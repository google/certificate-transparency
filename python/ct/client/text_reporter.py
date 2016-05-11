import gflags
import logging

from collections import defaultdict
from ct.client import reporter

FLAGS = gflags.FLAGS

class TextCertificateReport(reporter.CertificateReport):
    """Stores description of new entries between last verified STH and
    current."""

    def __init__(self):
        super(TextCertificateReport, self).__init__()

    def report(self):
        """Report stored changes and reset report."""
        super(TextCertificateReport, self).report()
        logging.info("Report:")
        logging.info("New entries since last verified STH: %s" %
                     self.new_entries_count)
        self.reset()

    def reset(self):
        """Clean up report.

        It's also ran at start."""
        self.new_entries_count = 0

    def _batch_scanned_callback(self, result):
        for _, log_index in result:
            msg = "Cert %d" % log_index
            self.new_entries_count += 1
