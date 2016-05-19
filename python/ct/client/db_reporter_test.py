#!/usr/bin/env python
import mock
import sys
import unittest
from ct.client import db_reporter
import gflags


class DbReporterTest(unittest.TestCase):
    def test_report(self):
        db = mock.MagicMock()
        reporter = db_reporter.CertDBCertificateReport(db, 1, checks=[])
        for j in range(1, 6):
            for i in range(0, 10):
                reporter._batch_scanned_callback([(None, None, None)])
            reporter.report()
            self.assertEqual(db.store_certs_desc.call_count, 10 * j)


if __name__ == '__main__':
  sys.argv = gflags.FLAGS(sys.argv)
  unittest.main()
