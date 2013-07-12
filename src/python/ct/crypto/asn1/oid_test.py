#!/usr/bin/env python

import unittest
from ct.crypto.asn1 import oid

class OidTest(unittest.TestCase):
    def test_dictionary(self):
        rsa = oid.ObjectIdentifier(oid.RSA_ENCRYPTION)
        self.assertEqual("rsaEncryption", rsa.long_name())
        self.assertEqual("RSA", rsa.short_name())

    def test_unknown_oids(self):
        unknown = oid.ObjectIdentifier("1.2.3.4")
        self.assertEqual("1.2.3.4", unknown.long_name())
        self.assertEqual("1.2.3.4", unknown.short_name())

    def test_string_value(self):
        unknown = oid.ObjectIdentifier("1.2.3.4")
        self.assertTrue("1.2.3.4" in unknown.string_value())

        rsa = oid.ObjectIdentifier(oid.RSA_ENCRYPTION)
        # String value should probably contain something about RSA...
        self.assertTrue("rsa" in rsa.string_value().lower())

if __name__ == '__main__':
    unittest.main()
