#!/usr/bin/env python

import unittest

from ct.crypto import error
from ct.crypto.asn1 import tag


class TagTest(unittest.TestCase):
    """Test tag encoding."""

    def test_encode_read(self):
        valid_tags = (
            # (initializers, encoding)
            ((0, tag.UNIVERSAL, tag.PRIMITIVE), "\x00"),
            ((1, tag.UNIVERSAL, tag.PRIMITIVE), "\x01"),
            ((16, tag.UNIVERSAL, tag.CONSTRUCTED), "\x30"),
            ((17, tag.UNIVERSAL, tag.CONSTRUCTED), "\x31"),
            ((0, tag.APPLICATION, tag.PRIMITIVE), "\x40"),
            ((1, tag.APPLICATION, tag.PRIMITIVE), "\x41"),
            ((0, tag.APPLICATION, tag.CONSTRUCTED), "\x60"),
            ((1, tag.APPLICATION, tag.CONSTRUCTED), "\x61"),
            ((0, tag.CONTEXT_SPECIFIC, tag.PRIMITIVE), "\x80"),
            ((1, tag.CONTEXT_SPECIFIC, tag.PRIMITIVE), "\x81"),
            ((0, tag.CONTEXT_SPECIFIC, tag.CONSTRUCTED), "\xa0"),
            ((1, tag.CONTEXT_SPECIFIC, tag.CONSTRUCTED), "\xa1"),
            ((0, tag.PRIVATE, tag.PRIMITIVE), "\xc0"),
            ((1, tag.PRIVATE, tag.PRIMITIVE), "\xc1"),
            ((0, tag.PRIVATE, tag.CONSTRUCTED), "\xe0"),
            ((1, tag.PRIVATE, tag.CONSTRUCTED), "\xe1"),
            )

        for init, enc in valid_tags:
            number, tag_class, encoding = init
            t = tag.Tag(number, tag_class, encoding)
            self.assertEqual(t.number, number)
            self.assertEqual(t.tag_class, tag_class)
            self.assertEqual(t.encoding, encoding)
            self.assertEqual(t.value, enc)
            self.assertEqual((t, ""), tag.Tag.read(enc))
            self.assertEqual((t, "rest"), tag.Tag.read(enc + "rest"))

        for i in range(len(valid_tags)):
            for j in range(i+1, len(valid_tags)):
                self.assertNotEqual(tag.Tag(*valid_tags[i][0]),
                                    tag.Tag(*valid_tags[j][0]))

    def test_read_invalid(self):
        self.assertRaises(error.ASN1Error, tag.Tag.read, "")
        # Not invalid but we don't support it yet.
        self.assertRaises(NotImplementedError, tag.Tag.read, "\x1f")
        self.assertRaises(NotImplementedError, tag.Tag.read, "\xff")


if __name__ == '__main__':
    unittest.main()
