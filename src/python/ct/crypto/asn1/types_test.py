#!/usr/bin/env python

import unittest

from ct.crypto import error
from ct.crypto.asn1 import tag
from ct.crypto.asn1 import types
from ct.crypto.asn1 import type_test_base


class TagDecoratorTest(unittest.TestCase):
    """Test the automatic creation of tags."""

    def test_universal_tag(self):
        class Test(object):
            tags = ()

        tagger = types.Universal(5, tag.PRIMITIVE)
        tagger(Test)

        self.assertEqual(1, len(Test.tags))
        expected_tag = tag.Tag(5, tag.UNIVERSAL, tag.PRIMITIVE)
        self.assertEqual(expected_tag, Test.tags[0])

    def test_explicit_tag(self):
        class Test(object):
            tags = ()

        tagger1 = types.Explicit(5, tag_class=tag.APPLICATION)
        tagger1(Test)

        self.assertEqual(1, len(Test.tags))
        expected_tag1 = tag.Tag(5, tag.APPLICATION, tag.CONSTRUCTED)
        self.assertEqual(expected_tag1, Test.tags[0])

        tagger2 = types.Explicit(3, tag_class=tag.CONTEXT_SPECIFIC)
        tagger2(Test)

        self.assertEqual(2, len(Test.tags))
        self.assertEqual(expected_tag1, Test.tags[0])

        expected_tag2 = tag.Tag(3, tag.CONTEXT_SPECIFIC, tag.CONSTRUCTED)
        self.assertEqual(expected_tag2, Test.tags[1])

    def test_implicit_tag(self):
        class Test(object):
            tags = ()

        tagger = types.Implicit(5, tag_class=tag.APPLICATION)
        # Cannot implicitly tag an untagged type.
        self.assertRaises(TypeError, tagger, Test)

        # Add a tag and try again.
        Test.tags = (tag.Tag(0, tag.UNIVERSAL, tag.PRIMITIVE),)
        tagger(Test)

        self.assertEqual(1, len(Test.tags))
        expected_tag = tag.Tag(5, tag.APPLICATION, tag.PRIMITIVE)
        self.assertEqual(expected_tag, Test.tags[0])

        # Repeat the test with a constructed encoding.
        Test.tags = (tag.Tag(0, tag.UNIVERSAL, tag.CONSTRUCTED),)
        tagger(Test)

        self.assertEqual(1, len(Test.tags))
        expected_tag = tag.Tag(5, tag.APPLICATION, tag.CONSTRUCTED)
        self.assertEqual(expected_tag, Test.tags[0])

# A dummy class we use to test that values are encoded as tag-length-value
# triplets.
class Dummy(types.Simple):
    # Fake.
    tags = (tag.Tag(1, tag.UNIVERSAL, tag.PRIMITIVE),)

    def _convert_value(cls, value):
        if isinstance(value, str):
            return value
        raise TypeError("Can't make a dummy from %s" % type(value))

    def _decode_value(self, buf, strict=True):
        return buf

    def _encode_value(self):
        return self._value

    def __str__(self):
        # Inject a marker to test human_readable().
        return "dummy!" + str(self._value)

# And a simple sequence to test some properties of constructe objects.
class DummySequence(types.Sequence):
    LOOK = {True: types.Integer}
    components = (
        types.Component("bool", types.Boolean),
        types.Component("int", types.Integer, optional=True),
        types.Component("oct", types.OctetString, default="hi"),
        types.Component("any", types.Any, defined_by="bool", lookup=LOOK)
      )


class TagLengthValueTest(unittest.TestCase):
    """Test Tag-Length-Value encoding."""
    # A slightly more interesting encoding to test reading from the beginning
    # of a buffer.
    class TruncatingDummy(types.Simple):
        tags = (tag.Tag(1, tag.UNIVERSAL, tag.PRIMITIVE),)
        def _convert_value(cls, value):
            return value[0]

        def _decode_value(self, buf, strict=True):
            if not buf:
                raise error.ASN1Error("Empty values are not allowed")
            return buf[0], buf[1:]

        def _encode_value(self):
            return self._value

    def test_encode_decode_int(self):
        signed_integer_encodings = (
            (0, "00"),
            (127, "7f"),
            (128, "0080"),
            (256, "0100"),
            (-1, "ff"),
            (-128, "80"),
            (-129, "ff7f")
            )

        for value, enc in signed_integer_encodings:
            self.assertEqual(types.encode_int(value).encode("hex"), enc)
            self.assertEqual(types.decode_int(enc.decode("hex")), value)

        unsigned_integer_encodings = (
            (0, "00"),
            (127, "7f"),
            (128, "80"),
            (256, "0100")
            )

        for value, enc in unsigned_integer_encodings:
            self.assertEqual(
                types.encode_int(value, signed=False).encode("hex"), enc)
            self.assertEqual(
                types.decode_int(enc.decode("hex"), signed=False), value)

    def test_encode_read_length(self):
        length_encodings = (
            (0, "00"),
            (1, "01"),
            (38, "26"),
            (127, "7f"),
            (129, "8181"),
            (201, "81c9"),
            (65535, "82ffff"),
            (65536, "83010000")
            )

        for value, enc in length_encodings:
            self.assertEqual(types.encode_length(value).encode("hex"), enc)
            self.assertEqual(types.read_length(enc.decode("hex")), (value, ""))
            # Test that the reader stops after the specified number of bytes.
            longer = enc + "00"
            self.assertEqual(types.read_length(longer.decode("hex")),
                             (value, "\x00"))
            longer = enc + "ff"
            self.assertEqual(types.read_length(longer.decode("hex")),
                             (value, "\xff"))
            # And test that it complains when there are not enough bytes.
            shorter = enc[:-2]
            self.assertRaises(error.ASN1Error,
                              types.read_length, shorter.decode("hex"))

    def test_encode_decode_read(self):
        value = "hello"
        d = Dummy(value=value)
        enc = d.encode()
        encoded_length = types.encode_length(len(value))

        expected = Dummy.tags[0].value + encoded_length + value
        self.assertEqual(expected.encode("hex"), enc.encode("hex"))

        decoded_dummy = Dummy.decode(enc)
        self.assertTrue(isinstance(decoded_dummy, Dummy))
        self.assertEqual(decoded_dummy.value, value)

        read_dummy, rest = Dummy.read(enc)
        self.assertTrue(isinstance(read_dummy, Dummy))
        self.assertEqual(read_dummy.value, value)
        self.assertEqual("", rest)

    def test_read_from_beginning(self):
        value = "hello"
        d = self.TruncatingDummy(value=value)
        self.assertEqual("h", d.value)
        enc = d.encode()

        encoded_length = types.encode_length(len(d.value))
        expected = Dummy.tags[0].value + encoded_length + d.value
        self.assertEqual(expected.encode("hex"), enc.encode("hex"))

        longer_buffer = enc + "ello"
        # We can't decode because there are leftover bytes...
        self.assertRaises(error.ASN1Error, Dummy.decode, longer_buffer)

        # ... but we can read from the beginning of the buffer.
        read_dummy, rest = Dummy.read(longer_buffer)
        self.assertTrue(isinstance(read_dummy, Dummy))
        self.assertEqual("h", read_dummy.value)
        self.assertEqual("ello", rest)

    def test_encode_decode_read_multiple_tags(self):
        @types.Explicit(8)
        class NewDummy(Dummy):
            pass

        value = "hello"
        d = NewDummy(value=value)
        enc = d.encode()
        encoded_inner_length = types.encode_length(len(value))

        inner = Dummy.tags[0].value + encoded_inner_length + value
        encoded_length = types.encode_length(len(inner))

        expected = NewDummy.tags[1].value + encoded_length + inner
        self.assertEqual(expected.encode("hex"), enc.encode("hex"))

        decoded_dummy = NewDummy.decode(enc)
        self.assertTrue(isinstance(decoded_dummy, NewDummy))
        self.assertEqual(decoded_dummy.value, value)

        read_dummy, rest = NewDummy.read(enc)
        self.assertTrue(isinstance(read_dummy, NewDummy))
        self.assertEqual(read_dummy.value, value)
        self.assertEqual("", rest)


class BooleanTest(type_test_base.TypeTestBase):
    asn1_type = types.Boolean
    repeated = False
    keyed = False
    initializers = (
        (False, 0),
        (True, 1),
        )
    bad_initializers = (
      # Everything is converted to a bool and accepted.
      )
    encode_test_vectors = (
        (True, "0101ff"),
        (False, "010100")
        )
    bad_encodings = (
        # Empty value.
        ("0100"),
        # Longer than 1 byte.
        ("01020000"),
        ("0102ffff")
        )
    bad_strict_encodings = (
        # Nonzero byte for True.
        (True, "010101"),
        (True, "0101ab")
        )


class IntegerTest(type_test_base.TypeTestBase):
    asn1_type = types.Integer
    repeated = False
    keyed = False
    initializers = (
        (0,),
        (1,),
        (-1,),
        (1000000,),
        )
    bad_initializers = (
        # Everything that can be converted to an int is accepted.
        )
    encode_test_vectors = (
        (0, "020100"),
        (127, "02017f"),
        (128, "02020080"),
        (256, "02020100"),
        (-1, "0201ff"),
        (-128, "020180"),
        (-129, "0202ff7f")
        )
    bad_encodings = (
        # Empty value.
        ("0200"),
        )
    bad_strict_encodings = (
        # Leading 0-octets.
        (0, "02020000"),
        (127, "0202007f"),
        # Leading ff-octets.
        (-1, "0202ffff"),
        (-128, "0202ff80")
      )


class OctetStringTest(type_test_base.TypeTestBase):
    asn1_type = types.OctetString
    repeated = False
    keyed = False
    initializers = (
        ("hello",),
        ("\xff\x00",),
        )
    bad_initializers = (
        # Nothing exciting.
        )
    encode_test_vectors = (
        # Empty strings are allowed.
        ("", "0400"),
        ("hello", "040568656c6c6f"),
        ("\xff\x00", "0402ff00")
        )
    bad_encodings = ()
    bad_strict_encodings = ()

# Skip other string type tests as there's currently no exciting specialization
# for those.


class BitStringTest(type_test_base.TypeTestBase):
    asn1_type = types.BitString
    repeated = False
    keyed = False
    initializers = (
        ("",),
        ("0",),
        ("1",),
        ("010100010110",),
        )
    bad_initializers = (
        ("hello", ValueError),
        ("0123cdef", ValueError),
        ("\xff\x00", ValueError)
        )
    encode_test_vectors = (
        # From the ASN.1 spec.
        # 0a3b5f291cd
        ("00001010001110110101111100101001000111001101", "0307040a3b5f291cd0"),
        # More test vectors with different amounts of padding
        ("", "030100"),
        ("0", "03020700"),
        ("1", "03020780"),
        ("0000000", "03020100"),
        ("0000001", "03020102"),
        ("1000000", "03020180"),
        ("00000000", "03020000"),
        ("11111111", "030200ff"),
        ("0000000001", "0303060040"),
        )
    bad_encodings = (
        # Empty value - padding byte must always be present.
        ("0300"),
        # Padding but no other bytes.
        ("030101"),
        ("030107"),
        # Invalid padding value.
        ("030108"),
        ("030180"),
        ("03020800"),
        ("03028000"),
        # Invalid padding bits.
        ("030201ff"),
        ("030205f0"),
        ("030207f0")
        )
    bad_strict_encodings = ()


class SequenceOfTest(type_test_base.TypeTestBase):
    # Test with a dummy class.
    class SequenceOfDummies(types.SequenceOf):
        component = Dummy
    asn1_type = SequenceOfDummies
    immutable = False
    keyed = False
    initializers = (
        ([Dummy(value="world"), Dummy(value="hello"), Dummy(value="\x00")],
         ["world", "hello", "\x00"],
         [Dummy(value="world"), "hello", "\x00"]),
        ([], ()),
      )
    bad_initializers = (
        # Can't coerce to Dummy.
        ([3], TypeError),
        ([True], TypeError),
        # Can't iterate.
        (True, TypeError)
        )
    encode_test_vectors = (
        ([], "3000"),
        ([Dummy(value="hello"), Dummy(value="\x00\xff")],
         "300b010568656c6c6f010200ff"),
        # Different order produces a different encoding.
        ([Dummy(value="\x00\xff"), Dummy(value="hello")],
         "300b010200ff010568656c6c6f")
        )
    bad_encodings = (
        # Bad element length.
        "3003010200",
        # Bad component tag.
        "30020200"
        )
    bad_strict_encodings = (
        )


class SetOfTest(type_test_base.TypeTestBase):
    class SetOfDummies(types.SetOf):
        component = Dummy
    asn1_type = SetOfDummies
    immutable = False
    keyed = False
    initializers = (
        ([Dummy(value="world"), Dummy(value="\x00"), Dummy(value="world")],
         ["world", "\x00", "world"],
         [Dummy(value="world"), "\x00", "world"]),
        ([], ()),
      )
    bad_initializers = (
        # Can't coerce to Dummy.
        ([3], TypeError),
        ([True], TypeError),
        # Can't iterate.
        (True, TypeError)
        )
    encode_test_vectors = (
        ([], "3100"),
        # Elements are sorted according to their encoding.
        ([Dummy(value="\x00\xff"), Dummy(value="hello")],
         "310b010200ff010568656c6c6f"),
        )
    bad_encodings = (
        # Bad element length.
        "31010200",
        # Bad component tag.
        "31020200"
        )
    bad_strict_encodings = (
        )

    def test_encoding_is_order_independent(self):
        elems = [Dummy(value="world"), Dummy(value="hello")]
        dummies = self.asn1_type(elems)
        elems2 = [Dummy(value="hello"), Dummy(value="world")]
        dummies2 = self.asn1_type(elems2)
        # Encodings compare equal even though the sets don't.
        self.assertEqual(dummies.encode(), dummies2.encode())


class AnyTest(type_test_base.TypeTestBase):
    asn1_type = types.Any
    repeated = False
    keyed = False
    initializers = (
        # Decoded and undecoded initializers.
        # Test with a few simple types.
        (types.Boolean(value=True).encode(), types.Boolean(value=True)),
        (types.Integer(value=3).encode(), types.Integer(value=3)),
        (types.OctetString("hello").encode(), types.OctetString("hello")),
        # We don't currently check that the encoded value encodes a valid
        # tag-length-value triplet, so this will also succeed,
        ("0000ff",),
        ("",)
        )
    bad_initializers = (
        (types.Any("hello"), TypeError),
        )
    encode_test_vectors = (
        # A Boolean True.
        ("\x01\x01\xff", "0101ff"),
        # An Integer 3.
        ("\x02\x01\x03", "020103"),
        # An octet string "hello".
        ("\x04\x05\x68\x65\x6c\x6c\x6f", "040568656c6c6f"),
        )
    bad_encodings = ()
    bad_strict_encodings = ()

    def test_decode_inner(self):
        dummy = Dummy(value="hello")
        a = types.Any(dummy)
        self.assertTrue(a.decoded)
        self.assertEqual(a.decoded_value, dummy)
        enc = dummy.encode()
        a2 = types.Any(enc)
        self.assertFalse(a2.decoded)
        self.assertEqual(a, a2)
        self.assertEqual(a.value, a2.value)
        a2.decode_inner(value_type=Dummy)
        self.assertTrue(a2.decoded)
        self.assertEqual(a2.decoded_value, dummy)


class ChoiceTest(type_test_base.TypeTestBase):
    class MyChoice(types.Choice):
        components = {
            "bool": types.Boolean,
            "int": types.Integer,
            "oct": types.OctetString,
          }
    asn1_type = MyChoice
    immutable = False
    repeated = False
    keyed = True
    initializers = (
        ({"bool": types.Boolean(value=False)}, {"bool": False}),
        ({"int": types.Integer(value=3)}, {"int": 3}),
        ({"oct": types.OctetString(value="hello")}, {"oct": "hello"}),
        ({}, {"bool": None}, {"int": None}, {"oct": None})
        )
    bad_initializers = (
        # Multiple values set at once.
        ({"bool": False, "int": 3}, ValueError),
        # Invalid key.
        ({"boo": False}, ValueError),
        )
    encode_test_vectors = (
        ({"bool": True}, "0101ff"),
        ({"int": 3}, "020103"),
        ({"oct": "hello"}, "040568656c6c6f"),
        )
    bad_encodings = ()
    bad_strict_encodings = ()


class SequenceTest(type_test_base.TypeTestBase):
    asn1_type = DummySequence
    immutable = False
    repeated = False
    keyed = True
    initializers = (
        # Fully specified, Any can be decoded.
        ({"bool": True, "int": 3, "oct": "hello", "any": "\x02\x01\x05"},),
        # Fully specified, Any cannot be decoded.
        ({"bool": False, "int": 3, "oct": "hello", "any": "\x02\x01\x05"},),
        # Partially specified.
        ({"bool": True, "int": None, "oct": "hi", "any": None},
         {"bool": True},),
        ({"bool": None, "int": 3, "oct": "hi", "any": None}, {"int": 3},),
        # Setting the defaults is the same as setting nothing.
        ({"bool": None, "int": None, "oct": "hi", "any": None},
         {"bool": None, "int": None, "oct": None, "any": None},
         {},
         {"oct": "hi"}),
        )
    bad_initializers = (
        # Invalid key.
        ({"boo": False}, ValueError),
        # Invalid component.
        ({"int": "hello"}, ValueError)
        )
    encode_test_vectors = (
        ({"bool": True, "int": 3, "oct": "hello", "any": "\x02\x01\x05"},
         "30100101ff020103040568656c6c6f020105"),
        # Missing optional.
        ({"bool": True, "oct": "hello", "any": "\x02\x01\x05"},
         "300d0101ff040568656c6c6f020105"),
        # Missing default.
        ({"bool": True, "int": 3, "any": "\x02\x01\x05"},
         "30090101ff020103020105"),
        # Default value set.
        ({"bool": True, "int": 3, "oct": "hi", "any": "\x02\x01\x05"},
         "30090101ff020103020105"),
        )
    bad_encodings = ()
    bad_strict_encodings = ()

    def test_decode_any(self):
        seq = self.asn1_type({"bool": True, "int": 3, "oct": "hello",
                              "any": "\x02\x01\x05"})
        enc = seq.encode()
        dec = self.asn1_type.decode(enc)
        self.assertTrue(dec["any"].decoded)
        self.assertEqual(dec["any"].decoded_value, 5)

        # Lookup key not in dictionary.
        seq = self.asn1_type({"bool": False, "int": 3, "oct": "hello",
                              "any": "\x02\x01\x05"})
        enc = seq.encode()
        seq = self.asn1_type.decode(enc)
        self.assertFalse(seq["any"].decoded)

        # Corrupt any.
        # We don't currently verify the Any spec when creating an element.
        seq = self.asn1_type({"bool": True, "int": 3, "oct": "hello",
                              "any": "\x01\x01\x05"})
        enc = seq.encode()
        # Can't decode in strict mode.
        self.assertRaises(error.ASN1Error, self.asn1_type.decode, enc)
        dec = self.asn1_type.decode(enc, strict=False)
        self.assertFalse(dec["any"].decoded)


class PrintTest(unittest.TestCase):
    def test_simple_human_readable(self):
        dummy = Dummy("hello")
        # Ensure there's some content.
        self.assertTrue(str(dummy))
        self.assertTrue(str(dummy) in dummy.human_readable(wrap=0))

    def test_simple_human_readable_prints_label(self):
        s = Dummy("hello").human_readable(label="world")
        self.assertTrue("world" in s)

    def test_simple_human_readable_lines_wrap(self):
        dummy = Dummy(value="hello")
        wrap = 3
        for line in dummy.human_readable_lines(wrap=wrap):
            self.assertTrue(len(line) <= wrap)

    def test_string_value_int(self):
        i = types.Integer(value=123456789)
        self.assertTrue("123456789" in str(i))

    def test_string_value_bool(self):
        b = types.Boolean(value=True)
        self.assertTrue("true" in str(b).lower())
        b = types.Boolean(value=False)
        self.assertTrue("false" in str(b).lower())

    def test_string_value_string(self):
        # Currently all string types are just str, with no encoding.
        hello = "\x68\x65\x6c\x6c\x6f"
        opaque = "\xd7\xa9\xd7\x9c\xd7\x95\xd7\x9d"
        string_types = [types.TeletexString, types.PrintableString,
                        types.UniversalString, types.UTF8String,
                        types.BMPString, types.IA5String]

        for t in string_types:
            s = t(value=hello)
            self.assertTrue("hello" in str(s))
            # TODO(ekasper): make this fail for PrintableString and possibly
            # others according to their character set restrictions.
            s2 = t(value=opaque)
            self.assertTrue(opaque in str(s2))

    def test_string_value_bitstring(self):
        # 0x1ae
        b = str(types.BitString(value="0110101110"))
        self.assertTrue("1" in b)
        self.assertTrue("ae" in b.lower())

    def test_string_value_octetstring(self):
        b = str(types.OctetString(value="\x42\xac"))
        self.assertTrue("42" in b)
        self.assertTrue("ac" in b.lower())

    def test_constructed_human_readable(self):
        dummy = DummySequence({"bool": True, "int": 3})
        s = dummy.human_readable(wrap=0)
        self.assertTrue("bool" in s)
        self.assertTrue("true" in s.lower())
        self.assertTrue("int" in s)
        self.assertTrue("3" in s)
        # Present since a default is set.
        self.assertTrue("oct" in s)
        # Not present and no default.
        self.assertFalse("any" in s)


if __name__ == '__main__':
    unittest.main()
