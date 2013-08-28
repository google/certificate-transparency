#!/usr/bin/env python
"""Tests for x509 GeneralName class."""

import gflags
import time
import unittest
import sys
from ct.crypto import cert
from ct.crypto import name
from ct.crypto.asn1 import x509_name

FLAGS = gflags.FLAGS
gflags.DEFINE_string('testdata_dir', "ct/crypto/testdata",
                     "Location of test certs")

class GeneralNameTest(unittest.TestCase):
    _MULTIPLE_AN_PEM_FILE = "multiple_an.pem"

    @property
    def pem_file(self):
        return FLAGS.testdata_dir + "/" + self._MULTIPLE_AN_PEM_FILE

    def test_multiple_alternative_names(self):
        c = cert.Certificate.from_pem_file(self.pem_file)
        names = c.subject_alternative_names()
        expected_types = [x509_name.DNS_NAME, x509_name.DIRECTORY_NAME,
            x509_name.IP_ADDRESS_NAME, x509_name.URI_NAME]
        self.assertItemsEqual(expected_types, [n.type() for n in names])
        # dnsname
        self.assertEqual(names[0].value(), "spires.wpafb.af.mil")
        # DirectoryName - should be a list.
        self.assertTrue(type(names[1].value()) is list)
        # IP address
        self.assertEqual(names[2].value(), (129, 48, 105, 104))
        # URI
        self.assertEqual(names[3].value(), "spires.wpafb.af.mil")

if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
    unittest.main()
