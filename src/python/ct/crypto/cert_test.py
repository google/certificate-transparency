#!/usr/bin/env python

import gflags
import time
import unittest
import sys
from ct.crypto import cert, error

FLAGS = gflags.FLAGS
gflags.DEFINE_string("testdata_dir", "ct/crypto/testdata",
                     "Location of test certs")

class CertificateTest(unittest.TestCase):
    _PEM_FILE = "google_cert.pem"

    # Contains 3 certificates
    # C=US/ST=California/L=Mountain View/O=Google Inc/CN=www.google.com
    # C=US/O=Google Inc/CN=Google Internet Authority
    # C=US/O=Equifax/OU=Equifax Secure Certificate Authority
    _PEM_CHAIN_FILE = "google_chain.pem"
    _DER_FILE = "google_cert.der"
    # An X509v1 certificate
    _V1_PEM_FILE = "v1_cert.pem"

    # A old but common (0.5% of all certs as of 2013-10-01) SSL
    # cert that uses a different or older DER format for Boolean
    # values.
    _PEM_MATRIXSSL = "matrixssl_sample.pem"

    @property
    def pem_file(self):
        return FLAGS.testdata_dir + "/" + self._PEM_FILE

    @property
    def der_file(self):
        return FLAGS.testdata_dir + "/" + self._DER_FILE

    @property
    def chain_file(self):
        return FLAGS.testdata_dir + "/" + self._PEM_CHAIN_FILE

    @property
    def v1_file(self):
        return FLAGS.testdata_dir + "/" + self._V1_PEM_FILE

    @property
    def matrixssl_file(self):
        return FLAGS.testdata_dir + "/" + self._PEM_MATRIXSSL

    def test_from_pem_file(self):
        c = cert.Certificate.from_pem_file(self.pem_file)
        self.assertTrue(isinstance(c, cert.Certificate))

    def test_certs_from_pem_file(self):
        certs = [c for c in cert.certs_from_pem_file(self.chain_file)]
        self.assertEqual(3, len(certs))
        self.assertTrue(all(map(lambda x: isinstance(x, cert.Certificate),
                                certs)))
        self.assertTrue("google.com" in certs[0].subject_name())
        self.assertTrue("Google Inc" in certs[1].subject_name())
        self.assertTrue("Equifax" in certs[2].subject_name())

    def test_from_pem(self):
        with open(self.pem_file) as f:
            c = cert.Certificate.from_pem(f.read())
        self.assertTrue(isinstance(c, cert.Certificate))

    def test_all_from_pem(self):
        with open(self.chain_file) as f:
            certs = [c for c in cert.certs_from_pem(f.read())]
        self.assertEqual(3, len(certs))
        self.assertTrue(all(map(lambda x: isinstance(x, cert.Certificate),
                                certs)))
        self.assertTrue("google.com" in certs[0].subject_name())
        self.assertTrue("Google Inc" in certs[1].subject_name())
        self.assertTrue("Equifax" in certs[2].subject_name())

    def test_from_der_file(self):
        c = cert.Certificate.from_der_file(self.der_file)
        self.assertTrue(isinstance(c, cert.Certificate))

    def test_from_der(self):
        with open(self.der_file, "rb") as f:
            c = cert.Certificate.from_der(f.read())
        self.assertTrue(isinstance(c, cert.Certificate))

    def test_invalid_encoding_raises(self):
        self.assertRaises(error.EncodingError, cert.Certificate.from_der,
                          "bogus_der_string")
        self.assertRaises(error.EncodingError, cert.Certificate.from_pem,
                          "bogus_pem_string")

    def test_to_der(self):
        with open(self.der_file, "rb") as f:
            der_string = f.read()
        c = cert.Certificate(der_string)
        self.assertEqual(der_string, c.to_der())

    def test_parse_matrixssl(self):
        """Test parsing of old MatrixSSL.org sample certificate

        As of 2013-10-01, about 0.5% of all SSL sites use an old
        sample certificate from MatrixSSL.org. It appears it's used
        mostly for various home routers.  Unfortunately it uses a
        non-DER encoding for boolean value: the DER encoding of True
        is 0xFF but this cert uses a BER encoding of 0x01. This causes
        pure DER parsers to break.  This test makes sure we can parse
        this cert without exceptions or errors.
        """
        c = cert.Certificate.from_pem_file(self.matrixssl_file)
        issuer = c.issuer_name()
        self.assertTrue("MatrixSSL Sample Server" in issuer)

    def test_subject_name(self):
        c = cert.Certificate.from_der_file(self.der_file)
        subject = c.subject_name()
        # C=US, ST=California, L=Mountain View, O=Google Inc, CN=*.google.com
        self.assertTrue("US" in subject)
        self.assertTrue("California" in subject)
        self.assertTrue("Mountain View" in subject)
        self.assertTrue("Google Inc" in subject)
        self.assertTrue("*.google.com" in subject)

    def test_issuer_name(self):
        c = cert.Certificate.from_der_file(self.der_file)
        issuer = c.issuer_name()
        # Issuer: C=US, O=Google Inc, CN=Google Internet Authority
        self.assertTrue("US" in issuer)
        self.assertTrue("Google Inc" in issuer)
        self.assertTrue("Google Internet Authority" in issuer)

    def test_subject_common_name(self):
        c = cert.Certificate.from_der_file(self.der_file)
        self.assertEqual("*.google.com", c.subject_common_name())

    def test_validity(self):
        certs = list(cert.certs_from_pem_file(self.chain_file))
        self.assertEqual(3, len(certs))
        # notBefore: Sat Aug 22 16:41:51 1998 GMT
        # notAfter: Wed Aug 22 16:41:51 2018 GMT
        c = certs[2]
        # These two will start failing in 2018.
        self.assertTrue(c.is_temporally_valid_now())
        self.assertFalse(c.is_expired())

        self.assertFalse(c.is_not_yet_valid())

        # Aug 22 16:41:51 2018
        self.assertTrue(c.is_temporally_valid_at(time.gmtime(1534956111)))
        # Aug 22 16:41:52 2018
        self.assertFalse(c.is_temporally_valid_at(time.gmtime(1534956112)))

        # Aug 22 16:41:50 1998
        self.assertFalse(c.is_temporally_valid_at(time.gmtime(903804110)))
        # Aug 22 16:41:51 1998
        self.assertTrue(c.is_temporally_valid_at(time.gmtime(903804111)))

    def test_basic_constraints(self):
        certs = list(cert.certs_from_pem_file(self.chain_file))
        self.assertFalse(certs[0].basic_constraint_ca())
        self.assertTrue(certs[1].basic_constraint_ca())
        self.assertIsNone(certs[0].basic_constraint_path_length())
        self.assertEqual(0, certs[1].basic_constraint_path_length())

    def test_version(self):
        c = cert.Certificate.from_pem_file(self.pem_file)
        self.assertEqual(2, c.version())

    def test_serial_number(self):
        c = cert.Certificate.from_pem_file(self.pem_file)
        self.assertEqual(454887626504608315115709, c.serial_number())

    def test_v1_cert(self):
        c = cert.Certificate.from_pem_file(self.v1_file)
        self.assertEqual(0, c.version())
        self.assertIsNone(c.basic_constraint_ca())

    def test_alternative_names(self):
        certs = [c for c in cert.certs_from_pem_file(self.chain_file)]
        first_name = certs[0].subject_alternative_names()[0]
        self.assertEqual("dNSName", first_name.type())
        self.assertEqual("www.google.com", first_name.value())

    def test_no_alternative_names(self):
        c = cert.Certificate.from_pem_file(self.v1_file)
        self.assertEqual(0, len(c.subject_alternative_names()))

if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
    unittest.main()
