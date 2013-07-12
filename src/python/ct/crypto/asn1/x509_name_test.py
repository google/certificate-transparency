#!/usr/bin/env python

import unittest
from ct.crypto import error
from ct.crypto.asn1 import x509_name

class X509NameTest(unittest.TestCase):
    def test_attribute_dictionary(self):
        name = x509_name.ID_AT_NAME
        self.assertTrue(isinstance(name.value_type(), x509_name.X520Name))

    def test_unknown_attribute_type(self):
        unknown = x509_name.AttributeType("1.2.3.4")
        self.assertRaises(error.UnknownASN1AttributeTypeError,
                          unknown.value_type)

    # TODO(ekasper): test attribute decoding. This requires generating test
    # vectors with known good encodings of name attributes.
    # Note that name parsing functionality is also tested at a higher level
    # in ct.crypto.cert

if __name__ == '__main__':
    unittest.main()
