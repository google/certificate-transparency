from ct.client import reporter

class AggregatedCertificateReport(reporter.CertificateReport):
    """Reporter which passes the function calls to other reporters passed through
    constructor."""
    def __init__(self, reporters):
        self._reporters = reporters
        super(AggregatedCertificateReport, self).__init__()

    def report(self):
        super(AggregatedCertificateReport, self).report()
        for report in self._reporters:
            report.report()

    def reset(self):
        for report in self._reporters:
            report.reset()

    def _batch_scanned_callback(self, result):
        for report in self._reporters:
            report._batch_scanned_callback(result)
