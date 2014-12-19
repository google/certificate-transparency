#!/usr/bin/env python
import unittest
from ct.client.db import cert_desc
from ct.crypto import cert
CERT = cert.Certificate.from_der_file("ct/crypto/testdata/google_cert.der")
class CertificateDescriptionTest(unittest.TestCase):
    def test_from_cert(self):
        desc = cert_desc.CertificateDescription.from_cert(CERT)
        self.assertEqual(desc.der, CERT.to_der())
        self.assertEqual(desc.subject_names,
                         ['.'.join(cert_desc.process_name(sub.value))
                          for sub in CERT.subject_common_names()])
        self.assertEqual(desc.alt_subject_names,
                         ['.'.join(cert_desc.process_name(sub.value))
                          for sub in CERT.subject_dns_names()])
        self.assertEqual(desc.version, str(CERT.version().value))
        self.assertEqual(desc.serial_number, str(CERT.serial_number().value))
        self.assertEqual(desc.ip_addresses,
                         [str(ip) for ip in CERT.subject_ip_addresses()])


if __name__ == "__main__":
    unittest.main()
