#!/usr/bin/env python
import mock
import unittest

from ct.client import reporter
from ct.cert_analysis import asn1
from ct.cert_analysis import base_check_test
from ct.crypto import cert
from ct.crypto import error


class CertificateReportTest(base_check_test.BaseCheckTest):
    class FakeCheck(object):
        @staticmethod
        def check(certificate):
            return [asn1.Strict("Boom!")]

    def test_scan_der_cert_no_checks(self):
        report = reporter.CertificateReport([])
        cert.Certificate = mock.MagicMock()
        report.scan_der_cert(0, "hello\x00")
        self.assertEqual(len(report._observations_by_index), 0)

    def test_scan_der_cert_broken_cert(self):
        report = reporter.CertificateReport([])
        report.scan_der_cert(0, "asdf")
        self.assertObservationIn(asn1.All(),
                      sum(report._observations_by_index.values(), []))
        self.assertEqual(len(report._observations_by_index), 1)

    def test_scan_der_cert_check(self):
        report = reporter.CertificateReport([self.FakeCheck()])
        cert.Certificate = mock.MagicMock()
        report.scan_der_cert(0, "asdf")

        self.assertObservationIn(asn1.Strict("Boom!"),
                                 sum(report._observations_by_index.values(), []))
        self.assertEqual(len(report._observations_by_index), 1)

    def test_scan_der_cert_check_non_strict(self):
        report = reporter.CertificateReport([self.FakeCheck()])
        cert.Certificate = mock.MagicMock(side_effect = [error.ASN1Error("Boom!")
                                                         , None])
        report.scan_der_cert(0, "kokojambo i do przodu")
        self.assertObservationIn(asn1.Strict("Boom!"),
                                 sum(report._observations_by_index.values(), []))

    def test__add_certificate_observation(self):
        report = reporter.CertificateReport([])
        report._add_certificate_observation(0, asn1.Strict(None))
        self.assertEqual(len(report._observations_by_index), 1)
        self.assertEqual(len(report._observations_by_index.values()), 1)

    def test_report(self):
        report = reporter.CertificateReport([])
        report._add_certificate_observation(0, asn1.Strict(None))
        report._add_certificate_observation(1, asn1.All())
        report.report()
        # since currently report simply prints stored data and resets, here we
        # just make sure that method runs without raising anything and resets
        # the data
        self.assertEqual(len(report._observations_by_index), 0)

if __name__ == '__main__':
    unittest.main()
