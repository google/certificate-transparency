#!/usr/bin/env python
import unittest

from ct.crypto import error
from ct.crypto.asn1 import types
from ct.crypto.asn1 import x509_extension as ext
import mock
from pyasn1.codec.der import encoder
from pyasn1.type import namedtype


class X509ExtensionTest(unittest.TestCase):
    def test_extension_dictionary(self):
        extn = ext.ID_CE_BASIC_CONSTRAINTS
        self.assertEqual(extn.value_type(), ext.BasicConstraints)

    def test_unknown_extension_type(self):
        unknown = ext.ExtensionID("1.2.3.4")
        self.assertRaises(error.UnknownASN1TypeError, unknown.value_type)

    @mock.patch.object(ext.ExtensionID, "value_type")
    def test_get_decoded_value(self, mock_value_type):
        class FakeExtension(types.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("int", types.Integer()),
                namedtype.NamedType("str", types.PrintableString()))

        fake = FakeExtension()
        fake.setComponentByName("int", value=3)
        fake.setComponentByName("str", value="hello")
        encoded = encoder.encode(fake)

        extn = ext.Extension()
        extn.setComponentByName("extnID", "1.2.3.4")
        extn.setComponentByName("critical", True)
        extn.setComponentByName("extnValue", encoded)

        mock_value_type.return_value = FakeExtension
        decoded_extension = extn.get_decoded_value()
        self.assertTrue(isinstance(decoded_extension, FakeExtension))
        self.assertEqual(decoded_extension.getComponentByName("int"), 3)
        self.assertEqual(decoded_extension.getComponentByName("str"), "hello")

if __name__ == "__main__":
    unittest.main()
