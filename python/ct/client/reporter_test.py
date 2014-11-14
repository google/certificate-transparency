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


    def test_scan_der_cert_no_checks(self):
        report = reporter.CertificateReport([])
        report.scan_der_certs([(0, STRICT_DER)])
        result = report.report()
        self.assertEqual(len(sum(result.values(), [])), 0)

    def test_scan_der_cert_broken_cert(self):
        report = reporter.CertificateReport([])
        report.scan_der_certs([(0, "asdf")])
        result = report.report()
        self.assertObservationIn(asn1.All(),
                      sum(result.values(), []))
        self.assertEqual(len(sum(result.values(), [])), 1)

    def test_scan_der_cert_check(self):
        report = reporter.CertificateReport([FakeCheck()])
        report.scan_der_certs([(0, STRICT_DER)])
        result = report.report()
        self.assertObservationIn(asn1.Strict("Boom!"),
                                 sum(result.values(), []))
        self.assertEqual(len(result), 1)

    def test_scan_der_cert_check_non_strict(self):
        report = reporter.CertificateReport([FakeCheck()])
        report.scan_der_certs([(0, NON_STRICT_DER)])
        result = report.report()
        # There should be FakeCheck and asn.1 strict parsing failure
        self.assertEqual(len(sum(result.values(), [])), 2)
        self.assertObservationIn(asn1.Strict("Boom!"), sum(result.values(), []))


if __name__ == '__main__':
    unittest.main()
