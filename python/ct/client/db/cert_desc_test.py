#!/usr/bin/env python
import unittest
from ct.client.db import cert_desc
from ct.crypto.asn1 import types
from ct.crypto.asn1 import oid
from ct.crypto import cert
from ct.proto import x509_cert_pb2

CERT = cert.Certificate.from_pem_file("ct/crypto/testdata/google_chain.pem")


class CertDescTest(unittest.TestCase):

    def test_bit_string_to_hex(self):
        bit_str = types.BitString('111111110000000011111111' * 60)
        self.assertEqual(':'.join(['ff:00:ff'] * 60),
                         cert_desc.bit_string_to_hex(bit_str))

    def test_process_name(self):
        url = "asdf.koko.com"
        self.assertEqual(["com", "koko", "asdf",], cert_desc.process_name(url))

    def test_oid_to_string(self):
        self.assertEqual("2.5.29.32.0", cert_desc.oid_to_string(oid.ANY_POLICY))

    def test_from_cert(self):
        proto = cert_desc.from_cert(CERT)
        self.assertEqual(1372775967, proto.validity.not_before)
        self.assertEqual(1383263999, proto.validity.not_after)
        self.assertEqual(cert_desc.oid_to_string(oid.SHA1_WITH_RSA_ENCRYPTION),
                         proto.public_key_info.algorithm_id)
        self.assertEqual(cert_desc.bit_string_to_hex(CERT.subject_public_key()),
                         proto.public_key_info.public_key_text)
        self.assertEqual("google internet authority",
                         proto.issuer.common_name[0])
        self.assertEqual(1, len(proto.issuer.common_name))
        self.assertEqual(5, len(proto.issuer.attribute))
        self.assertEqual(1, len(proto.subject.common_name))
        self.assertEqual(5, len(proto.subject.attribute))
        self.assertEqual(2, proto.version)
        self.assertEqual(CERT.serial_number().human_readable()
                         .lower().replace(':', ''), proto.serial_number)
        self.assertEqual(cert_desc.oid_to_string(oid.SHA1_WITH_RSA_ENCRYPTION),
                         proto.signature_algorithm.algorithm_id)
        self.assertEqual(proto.extensions.extended_key_usage.object_id,
                         cert_desc.oid_to_string(oid.ID_CE_EXT_KEY_USAGE))
        self.assertEqual(proto.extensions.subject_key_id.object_id,
                         cert_desc.oid_to_string(oid.ID_CE_SUBJECT_KEY_IDENTIFIER))
        self.assertEqual(proto.extensions.authority_key_id.object_id,
                         cert_desc.oid_to_string(oid.ID_CE_AUTHORITY_KEY_IDENTIFIER))
        self.assertEqual(proto.extensions.authority_info_access.object_id,
                         cert_desc.oid_to_string(oid.ID_PE_AUTHORITY_INFO_ACCESS))
        self.assertEqual(proto.extensions.subject_alternative_name.object_id,
                         cert_desc.oid_to_string(oid.ID_CE_SUBJECT_ALT_NAME))
        self.assertEqual(proto.extensions.basic_constraints.ca_flag, False)
        self.assertEqual(proto.extensions.crl_distribution_point[0]
                         .distribution_point.full_name[0],
                         CERT.crl_distribution_points()[0]['distributionPoint']
                         ['fullName'][0].value['uniformResourceIdentifier'])

    def test_populate_x509_extension(self):
        proto = x509_cert_pb2.X509Certificate().extensions.extended_key_usage
        ext = CERT.get_extensions()[0]
        cert_desc.populate_x509_extension(proto, ext)
        self.assertEqual([ext['extnValue'].value], proto.value)
        self.assertEqual(ext['critical'].value, proto.critical)
        self.assertEqual(cert_desc.oid_to_string(ext['extnID']), proto.object_id)


if __name__ == '__main__':
    unittest.main()
