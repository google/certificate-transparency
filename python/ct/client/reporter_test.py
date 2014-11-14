#!/usr/bin/env python
import unittest

from ct.client import reporter
from ct.cert_analysis import asn1
from ct.cert_analysis import base_check_test
from ct.crypto import cert

STRICT_DER = cert.Certificate.from_der_file(
                    'ct/crypto/testdata/google_cert.der', False).to_der()
NON_STRICT_DER = cert.Certificate.from_pem_file(
                    'ct/crypto/testdata/invalid_ip.pem', False).to_der()

class FakeCheck(object):
    @staticmethod
    def check(certificate):
        return [asn1.Strict("Boom!")]


class CertificateReportTest(base_check_test.BaseCheckTest):
    class FakeCheck(object):
        @staticmethod
        def check(certificate):
            return [asn1.Strict("Boom!")]

    def wait_for_scans(self, report):
        """Helper method that waits till report pool finished working.

        This method closes report pool, so it's bad idea to scan certs
        after running this method"""
        report._pool.close()
        report._pool.join()

    def test_scan_der_cert_no_checks(self):
        report = reporter.CertificateReport([])
        report.scan_der_certs([(0, STRICT_DER)])
        self.wait_for_scans(report)
        self.assertEqual(len(sum(report._observations_by_index.values(), [])), 0)

    def test_scan_der_cert_broken_cert(self):
        report = reporter.CertificateReport([])
        report.scan_der_certs([(0, "asdf")])
        self.wait_for_scans(report)
        self.assertObservationIn(asn1.All(),
                      sum(report._observations_by_index.values(), []))
        self.assertEqual(len(sum(report._observations_by_index.values(), [])), 1)

    def test_scan_der_cert_check(self):
        report = reporter.CertificateReport([FakeCheck()])
        report.scan_der_certs([(0, STRICT_DER)])
        self.wait_for_scans(report)
        self.assertObservationIn(asn1.Strict("Boom!"),
                                 sum(report._observations_by_index.values(), []))
        self.assertEqual(len(report._observations_by_index), 1)

    def test_scan_der_cert_check_non_strict(self):
        report = reporter.CertificateReport([FakeCheck()])
        report.scan_der_certs([(0, NON_STRICT_DER)])
        self.wait_for_scans(report)
        self.assertIn(type(asn1.Strict("Boom!")),
                      map(type,sum(report._observations_by_index.values(), [])))

    def test__add_certificate_observations(self):
        report = reporter.CertificateReport([])
        report._add_certificate_observations([(0, [asn1.Strict(None)])])
        self.assertEqual(len(report._observations_by_index), 1)
        self.assertEqual(len(sum(report._observations_by_index.values(), [])), 1)

    def test_report(self):
        report = reporter.CertificateReport([])
        report._add_certificate_observations([(0, [asn1.Strict(None)])])
        report._add_certificate_observations([(1, [asn1.All()])])
        report.report()
        # since currently report simply prints stored data and resets, here we
        # just make sure that method runs without raising anything and resets
        # the data
        self.assertEqual(len(report._observations_by_index), 0)

if __name__ == '__main__':
    unittest.main()
