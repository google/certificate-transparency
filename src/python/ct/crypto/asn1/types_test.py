#!/usr/bin/env python

import unittest

from pyasn1.type import namedtype
from ct.crypto.asn1 import types

class TypesTest(unittest.TestCase):
    _DEFAULT_NAMED_COMPONENTTYPE = namedtype.NamedTypes(
                namedtype.NamedType('int1', types.Integer()),
                namedtype.NamedType('int2', types.Integer()))

    _DEFAULT_COMPONENTTYPE = types.Integer()

    class SimpleConcrete(types.SimpleBaseType):
        def string_value(self):
            return "hello"

    # Test that a human_readable() contains the string_value() result.
    def test_simple_human_readable(self):
        simple = self.SimpleConcrete()
        stringval = simple.string_value()
        self.assertTrue(stringval in simple.human_readable())

    def test_simple_human_readable_prints_label(self):
        s = self.SimpleConcrete().human_readable(label="world")
        self.assertTrue("world" in s)

    def test_simple_human_readable_lines_wrap(self):
        simple = self.SimpleConcrete()
        wrap = len(simple.string_value()) - 1
        for line in simple.human_readable_lines(wrap=wrap):
            self.assertTrue(len(line) <= wrap)

    def test_string_value_int(self):
        i = types.Integer(123456789).string_value()
        self.assertTrue("123456789" in i)

    def test_string_value_bool(self):
        b = types.Boolean("True").string_value()
        self.assertTrue("true" in b.lower())
        b = types.Boolean("False").string_value()
        self.assertTrue("false" in b.lower())

    def test_string_value_string(self):
        # Currently all string types are opaque bytestrings.
        hello = '\xd7\xa9\xd7\x9c\xd7\x95\xd7\x9d'
        string_types = [types.TeletexString, types.PrintableString,
                        types.UniversalString, types.UTF8String,
                        types.BMPString, types.IA5String]

        # TODO(ekasper): make this fail for PrintableString and possibly
        # others according to their character set restrictions.
        for t in string_types:
            s = t(hello).string_value()
            self.assertTrue(hello in s)

    def test_string_value_bitstring(self):
        # 0x1ae
        b = types.BitString("'0110101110'B").string_value()
        self.assertTrue("1" in b)
        self.assertTrue("ae" in b.lower())

    def test_string_value_octetstring(self):
        b = types.OctetString(hexValue="42ac").string_value()
        self.assertTrue("42" in b)
        self.assertTrue("ac" in b.lower())

    def __test_default_named_components(self, base_type):
        class ConcreteType(base_type):
            componentType = self._DEFAULT_NAMED_COMPONENTTYPE

        concrete = ConcreteType()
        components = [c for c in concrete.components()]
        self.assertEqual(0, len(components))

        concrete.setComponentByName("int2", value=2)

        components = [c for c in concrete.components()]
        self.assertEqual(1, len(components))
        self.assertEqual(("int2", 2), components[0])

    def __test_default_unnamed_components(self, base_type):
        class ConcreteType(base_type):
            componentType = self._DEFAULT_COMPONENTTYPE

        concrete = ConcreteType()
        components = [c for c in concrete.components()]
        self.assertEqual(0, len(components))

        concrete.setComponentByPosition(1, value=2)

        components = [c for c in concrete.components()]
        self.assertEqual(1, len(components))
        self.assertEqual(("1", 2), components[0])

    def test_sequence_components(self):
        self.__test_default_named_components(types.Sequence)

    def test_set_components(self):
        self.__test_default_named_components(types.Set)

    def test_sequenceof_components(self):
        self.__test_default_unnamed_components(types.SequenceOf)

    def test_setof_components(self):
        self.__test_default_unnamed_components(types.SetOf)

    def test_choice_components(self):
        self.__test_default_named_components(types.Choice)

    # We need a non-abstract type to test with but the implementation comes
    # from the abstract base class, so just test for Sequence.
    def test_constructed_human_readable(self):
        class ConcreteType(types.Sequence):
            PRINT_LABELS = True
            PRINT_DELIMITER = ""
            componentType = self._DEFAULT_NAMED_COMPONENTTYPE
        concrete = ConcreteType()
        concrete.setComponentByPosition(0, value=12345678)
        concrete.setComponentByPosition(1, value=9999)
        # Make sure we don't wrap lines.
        s = concrete.human_readable(wrap=0)
        self.assertTrue("int1" in s)
        self.assertTrue("int2" in s)
        self.assertTrue("12345678" in s)
        self.assertTrue("9999" in s)

if __name__ == '__main__':
    unittest.main()
