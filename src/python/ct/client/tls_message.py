"""TLS serialization."""

import math

from ct.proto import tls_options_pb2 as options
from google.protobuf import descriptor


class Error(Exception):
    pass


class TLSDecodingError(Error):
    """Decoding failed."""
    pass


class TLSReader(object):
    """Read serialized TLS messages into a protocol buffer."""

    def __init__(self, serialized_buffer):
        # It would be nice to use BytesIO but it has no efficient way of
        # testing whether it's empty without advancing the position, so
        # we have to keep track of the position manually.
        self._buf = serialized_buffer
        self._pos = 0

    def _read_fixed_bytes(self, num_bytes):
        if self._pos + num_bytes > len(self._buf):
            raise TLSDecodingError("Buffer underrun: need %d bytes, have "
                                   "%d bytes" % (num_bytes,
                                                 len(self._buf) - self._pos))
        ret = self._buf[self._pos:self._pos + num_bytes]
        self._pos += num_bytes
        return ret

    def finished(self):
        return self._pos >= len(self._buf)

    def verify_finished(self):
        if not self.finished():
            raise TLSDecodingError("Bytes remaining in the buffer")

    def _read_uint(self, num_bytes):
        int_bytes = bytearray(self._read_fixed_bytes(num_bytes))
        ret = 0
        for b in int_bytes:
            ret <<= 8
            ret += b
        return ret

    def _read_bounded_uint(self, min_value, max_value):
        length_of_value = int(math.ceil(math.log(max_value + 1, 256)))
        value = self._read_uint(length_of_value)
        if value < min_value or value > max_value:
            raise TLSDecodingError("Value %d is out of range ([%d, %d])" %
                                   (value, min_value, max_value))
        return value

    def _read_uint32(self, opts):
        return self._read_uint(opts.bytes_in_use or 4)

    def _read_uint64(self, opts):
        return self._read_uint(opts.bytes_in_use or 8)

    def _read_enum(self, opts):
        if not opts.max_value:
            raise TypeError("Enum field has no maximum value")
        return self._read_bounded_uint(0, opts.max_value)

    def _read_var_bytes(self, min_length, max_length):
        length = self._read_bounded_uint(min_length, max_length)
        return self._read_fixed_bytes(length)

    def _read_bytes(self, opts):
        if opts.fixed_length:
            return self._read_fixed_bytes(opts.fixed_length)
        elif opts.max_length:
            return self._read_var_bytes(opts.min_length, opts.max_length)
        else:
            raise TypeError("Byte field has no length limit")

    def get_read_method(self, field):
        if field.type == descriptor.FieldDescriptor.TYPE_UINT32:
            return self._read_uint32
        elif field.type == descriptor.FieldDescriptor.TYPE_UINT64:
            return self._read_uint64
        elif field.type == descriptor.FieldDescriptor.TYPE_ENUM:
            return self._read_enum
        elif field.type == descriptor.FieldDescriptor.TYPE_BYTES:
            return self._read_bytes
        else:
            raise TypeError("Field %s of type %d not supported" %
                            (field.name, field.type))

    def _read_repeated(self, message, field, opts):
        """Read a repeated field."""
        if not opts.max_total_length:
            raise TypeError("Repeated field %s has no length limit" %
                            field.name)
        # Recursive, naive.
        reader = TLSReader(self._read_var_bytes(opts.min_total_length,
                                                opts.max_total_length))

        target = getattr(message, field.name)

        if field.type == field.TYPE_MESSAGE:
            while not reader.finished():
                new_message = target.add()
                reader.read(new_message)
        else:
            if field.type == field.TYPE_ENUM:
                opts = field.enum_type.GetOptions().Extensions[
                    options.tls_enum_opts]
            read_method = reader.get_read_method(field)
            while not reader.finished():
                target.append(read_method(opts))

    def read(self, message):
        """Read from the buffer into the protocol buffer message."""
        # TODO(ekasper): probably better not to modify the
        # original message until we're guaranteed to succeed?
        for field in message.DESCRIPTOR.fields:
            opts = field.GetOptions().Extensions[options.tls_opts]
            if opts.skip:
                continue

            if opts.select_field:
                value = getattr(message, opts.select_field)
                if value != opts.select_value:
                    continue

            if field.label == field.LABEL_REPEATED:
                self._read_repeated(message, field, opts)

            elif field.type == field.TYPE_MESSAGE:
                self.read(getattr(message, field.name))

            else:
                if field.type == field.TYPE_ENUM:
                    opts = field.enum_type.GetOptions().Extensions[
                        options.tls_enum_opts]
                setattr(message, field.name,
                        self.get_read_method(field)(opts))

    @classmethod
    def decode(cls, buf, message):
        reader = cls(buf)
        reader.read(message)
        reader.verify_finished()
