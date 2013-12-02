"""ASN.1 tagging."""

from ct.crypto import error


UNIVERSAL = 0x00
APPLICATION = 0x40
CONTEXT_SPECIFIC = 0x80
PRIVATE = 0xc0
PRIMITIVE = 0x00
CONSTRUCTED = 0x20

# Constants for better readability.
IMPLICIT, EXPLICIT = range(2)


class Tag(object):
    """An ASN.1 tag."""
    _CLASS_MASK = 0xc0
    _ENCODING_MASK = 0x20
    _NUMBER_MASK = 0x1f
    _HIGH = 0x1f

    def __init__(self, number, tag_class, encoding):
        """ASN.1 tag.

        Initialize a tag from its number, class and encoding.

        Args:
            number: the numeric value of the tag.
            tag_class: must be one of UNIVERSAL, APPLICATION, CONTEXT_SPECIFIC
                or PRIVATE.
            encoding: must be one of PRIMITIVE or CONSTRUCTED.

        Raises:
            ValueError: invalid initializers.
        """
        if tag_class not in (UNIVERSAL, APPLICATION, CONTEXT_SPECIFIC, PRIVATE):
            raise ValueError("Invalid tag class %s" % tag_class)
        if encoding not in (PRIMITIVE, CONSTRUCTED):
            raise ValueError("Invalid encoding %s" % encoding)
        if number >= 31:
            raise NotImplementedError("High tags not implemented")

        # Public just for lightweight access. Do not modify directly.
        self.number = number
        self.tag_class = tag_class
        self.encoding = encoding
        self.value = chr(tag_class | encoding | number)

    def __repr__(self):
        return ("%s(%r, %r, %r)" % (self.__class__.__name__, self.number,
                                    self.tag_class, self.encoding))

    def __str__(self):
        return "[%s %d]" % (self.class_name(), self.number)

    def __len__(self):
        return len(self.value)

    def class_name(self):
        if self.tag_class == UNIVERSAL:
            return "UNIVERSAL"
        elif self.tag_class == APPLICATION:
            return "APPLICATION"
        elif self.tag_class == CONTEXT_SPECIFIC:
            return "CONTEXT-SPECIFIC"
        elif self.tag_class == PRIVATE:
            return "PRIVATE"
        else:
            raise ValueError("Invalid tag class %x" % self.tag_class)

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        if not isinstance(other, Tag):
            return NotImplemented
        return self.value == other.value

    def __ne__(self, other):
        if not isinstance(other, Tag):
            return NotImplemented
        return self.value != other.value

    @classmethod
    def read(cls, buf):
        """Read from the beginning of a string or buffer.

        Args:
            buf: a binary string or string buffer containing an ASN.1 object.

        Returns:
            an tuple consisting of an instance of the class and the remaining
            buffer/string.
        """

        if not buf:
            raise error.ASN1TagError("Ran out of bytes while decoding")
        id_byte = ord(buf[0])
        tag_class = id_byte & cls._CLASS_MASK
        encoding = id_byte & cls._ENCODING_MASK
        number = id_byte & cls._NUMBER_MASK
        if number == cls._HIGH:
            raise NotImplementedError("High tags not implemented")
        tag = cls(number, tag_class, encoding)
        return tag, buf[1:]
