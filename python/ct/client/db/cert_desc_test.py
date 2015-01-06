#!/usr/bin/env python
import unittest
from ct.client.db import cert_desc
from ct.crypto import cert

CERT = cert.Certificate.from_der_file("ct/crypto/testdata/google_cert.der")

class CertificateDescriptionTest(unittest.TestCase):
    def test_from_cert(self):
        proto = cert_desc.from_cert(CERT)
        self.assertEqual(proto.der, CERT.to_der())

        subject = [(att.type, att.value) for att in proto.subject]
        cert_subject = [(type_.short_name,
                     cert_desc.to_unicode('.'.join(
                             cert_desc.process_name(value.human_readable()))))
                    for type_, value in CERT.subject()]
        self.assertItemsEqual(cert_subject, subject)

        issuer = [(att.type, att.value) for att in proto.issuer]
        cert_issuer = [(type_.short_name,
                     cert_desc.to_unicode('.'.join(
                             cert_desc.process_name(value.human_readable()))))
                    for type_, value in CERT.issuer()]
        self.assertItemsEqual(cert_issuer, issuer)

        subject_alternative_names = [(att.type, att.value)
                                     for att in proto.subject_alternative_names]
        cert_subject_alternative_names = [(san.component_key(),
                                           cert_desc.to_unicode('.'.join(
                                            cert_desc.process_name(
                                     san.component_value().human_readable()))))
                    for san in CERT.subject_alternative_names()]
        self.assertItemsEqual(cert_subject_alternative_names,
                              subject_alternative_names)

        self.assertEqual(proto.version, str(CERT.version().value))
        self.assertEqual(proto.serial_number,
                         str(CERT.serial_number().human_readable()
                             .upper().replace(':', '')))


if __name__ == "__main__":
    unittest.main()
