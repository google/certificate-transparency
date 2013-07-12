"""
ASN.1 type hierarcy

Our type hierarchy closely follows pyasn1 type hierarchy. We use our parallel
type universe to add custom functionality to pyasn1-derived objects via
multiple inheritance.

Data model:

In the pyasn1 data model, the same type is used to represent a "type" object
(an ASN.1 template) and a "value" object (an ASN.1 value). For example,
univ.Integer() is a type object, while univ.Integer(3) is a value object.
Several built-in methods, however, are restricted to value objects.
For example,

>>> 3 == univ.Integer(3)
True

but

>>> univ.Integer() == univ.Integer()
pyasn1.error.PyAsn1Error: No value for __eq__()

and

>>> print univ.Integer()
pyasn1.error.PyAsn1Error: No value for __str__()

Similarly, we have in some cases added custom methods that can only be applied
value objects. These cases are documented, and usually semantically obvious.
An attempt to call value methods on type objects raises an ASN1Error.

String representations:

pyasn1 string representation handling is somewhat confusing:
it seems to be a stable (though undocumented) assumption of pyasn1 that
prettyPrint() is called recursively on constructed types, and that
simple objects call prettyOut() on their own value when prettyPrint()'ed.
__str__ is sometimes, but not necessarily, aliased to prettyPrint, and
prettyIn is not necessarily the inverse of prettyOut.

We define our own human_readable() to add semantic interpretation to the
ASN.1 objects. human_readable() works consistently for both type and value
objects.
"""
import abc
from pyasn1.type import base, char, namedtype, univ, useful
from pyasn1 import error as pyasn1_error
from ct.crypto.asn1 import print_util


class AbstractBaseType(object):
    """The base ASN.1 object."""
    ___metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def human_readable_lines(self, wrap=80, label=""):
        """A pretty human readable representation of the object.
        Args:
            wrap:   maximum number of characters per line. 0 or negative
                    wrap means no limit. Should be chosen long enough to
                    comfortably fit formatted data; otherwise it is simply
                    ignored and output may look funny.
            label:  a label prefix
        Returns:
            a list of line strings of at most |wrap| characters each."""
        pass

    def human_readable(self, wrap=80, label=""):
        """A pretty human readable representation of the object.
        Args:
            wrap:  maximum number of characters per line. 0 or negative
                   wrap means no limit. Should be chosen long enough to
                   comfortably fit formatted data; otherwise it is simply
                   ignored and output may look funny.
        Returns:
            a multi-line string of at most |wrap| characters per line."""
        return ('\n').join(self.human_readable_lines(wrap=wrap, label=label))

class SimpleBaseType(base.AbstractSimpleAsn1Item, AbstractBaseType):
    @classmethod
    def wrap_lines(cls, long_string, wrap):
        """Split long lines into multiple chunks according to the wrap limit.
        Derived classes can override if they wish to split at a specific point
        rather than at the wrap.
        Args:
            long_string: a string_value() representation of the object
            wrap:        maximum number of characters per line. 0 or negative
                         wrap means no limit. Should be chosen long enough to
                         comfortably fit formatted data; otherwise it is simply
                         ignored and output may look funny.
        Returns:
           long_string split into lines of at most |wrap| characters each."""
        return print_util.wrap_lines(long_string, wrap)

    def string_value(self):
        """Get a string representation of the object. Derived classes should
        override where appropriate.
        Returns:
            a human-readable string."""
        try:
            # This *should* always work for value objects.
            return str(self)
        except pyasn1_error.PyAsn1Error:
            return "<no value>"

    def human_readable_lines(self, wrap=80, label=""):
        """A pretty human readable representation of the object.
        Args:
            wrap:   maximum number of characters per line. 0 or negative
                    wrap means no limit. Should be chosen long enough to
                    comfortably fit formatted data; otherwise it is simply
                    ignored and output may look funny.
            label:  a label prefix
        Returns:
            a list of line strings of at most |wrap| characters each."""
        to_print = self.string_value()
        formatted_label = label + ": " if label else ""
        if (to_print.find('\n') == -1 and (wrap <= 0 or
            len(to_print) + len(formatted_label) <= wrap)):
            # Fits on one line, like this:
            # label: value
            return [formatted_label + to_print]

        else:
            # Multiline output:
            # label:
            #   firstlongvalueline
            #   secondvalueline
            ret = []
            indent = 2
            if label:
                ret += print_util.wrap_lines(label + ":", wrap)
            return ret + map(lambda x: ' '*indent + x,
                             self.wrap_lines(to_print, wrap-indent))

class BaseInt(univ.Integer, SimpleBaseType):
    def string_value(self):
        value = None
        try:
            # This will fail for a type object.
            value = int(self)
        except pyasn1_error.PyAsn1Error:
            return "<no value>"
        name = self.getNamedValues().getName(value)
        if name:
            return name
        else:
            return str(value)

class Integer(BaseInt):
    pass

class Boolean(univ.Boolean, BaseInt):
    pass

class BaseString(SimpleBaseType):
    def string_value(self):
        try:
            return str(self)
        except pyasn1_error.PyAsn1Error:
            return "<no value>"

# TODO(ekasper): pyasn1 does not properly constrain the valid alphabet for
# any of those types, so we should implement our own validation.
class TeletexString(char.TeletexString, BaseString):
    pass

class PrintableString(char.PrintableString, BaseString):
    pass

class UniversalString(char.UniversalString, BaseString):
    pass

class UTF8String(char.UTF8String, BaseString):
    pass

class BMPString(char.BMPString, BaseString):
    pass

class IA5String(char.IA5String, BaseString):
    pass

class BitString(univ.BitString, SimpleBaseType):
    @classmethod
    def wrap_lines(cls, long_string, wrap):
        # Always split hex characters at the delimiter
        if wrap >= 3:
            wrap = wrap - wrap % 3
        return super(BitString, cls).wrap_lines(long_string, wrap)

    def string_value(self):
        try:
            return print_util.bits_to_hex(self)
        except pyasn1_error.PyAsn1Error:
            return "<no value>"

class BaseOctetString(univ.OctetString, SimpleBaseType):
    @classmethod
    def wrap_lines(cls, long_string, wrap):
        if wrap >= 3:
            wrap = wrap - wrap % 3
        return super(BaseOctetString, cls).wrap_lines(long_string, wrap)

    def string_value(self):
        try:
            return print_util.bytes_to_hex(self.asOctets())
        except pyasn1_error.PyAsn1Error:
            return "<no value>"

class OctetString(BaseOctetString):
    pass

class Any(univ.Any, BaseOctetString):
    pass

# TODO(ekasper): print human readable timestamps.
class BaseTime(SimpleBaseType):
    pass

class UTCTime(useful.UTCTime, BaseTime):
    pass

class GeneralizedTime(useful.GeneralizedTime, BaseTime):
    pass

# From pyasn1 documentation:
# All pyasn1 constructed type classes have a class attribute componentType that
# represents default type specification. Its value is a NamedTypes object.
# But also:
# SequenceOf and SetOf types are expressed by the very similar pyasn1 type
# objects. Their components can only be addressed by position and they both have
# a property of automatic resize. To specify inner component type, the
# componentType class attribute should refer to another pyasn1 type object.
class ConstructedBaseType(base.AbstractConstructedAsn1Item, AbstractBaseType):
    # Class level options for printing. Can be overridden in derived classes to
    # customize printing behaviour.
    # Whether to print NamedType labels.
    PRINT_LABELS = True
    PRINT_DELIMITER = '\n'

    def label(self, idx):
        """String label of the |idx|^th component"""
        return str(idx)

    def components(self):
        """Get the components of the constructed object.
        Yields:
            (str(index), value) tuples. Yields only components
            whose value is set."""
        for idx in range(len(self)):
            value = self.getComponentByPosition(idx)
            if value is None:
                continue
            yield (self.label(idx), value)

    def human_readable_lines(self, wrap=80, label=""):
        """A pretty human readable representation of the object.
        Args:
            wrap:   maximum number of characters per line. 0 or negative
                    wrap means no limit. Should be chosen long enough to
                    comfortably fit formatted data; otherwise it is simply
                    ignored and output may look funny.
            label:  a label prefix
        Returns:
            a list of line strings of at most |wrap| characters each."""
        # A '\n' becomes ['', ''] which magically starts a new line when we call
        # append_lines() on it. Things like '\n-----\n' work, too.
        delimiter = (print_util.wrap_lines(self.PRINT_DELIMITER, wrap=wrap))
        lines = []

        # Component count. Needed so we can print "<no components>" when none
        # are found.
        count = 0
        # Whether the next component should start on a new line. Set to true
        # when the previous component was multiline. For example, a mix of short
        # and long components with a ", " delimiter is thus printed as
        # short1, short2, short3,
        # myextremelylongcomponentth
        # atspansmultiplelines
        # short4, short5
        newline = False

        if label:
            lines += print_util.wrap_lines(label + ":", wrap)
            # If the delimiter is multiline, then output looks prettier if the
            # label is also on a separate line.
            if len(delimiter) > 1:
                newline = True
            elif len(lines[-1]) < wrap:
                # Else add a whitespace so we get "label: value"
                lines[-1] += ' '

        indent = 2
        for name, value in self.components():
            label = name if self.PRINT_LABELS else ""
            print_component = value.human_readable_lines(wrap=wrap-indent,
                                                         label=label)
            if not print_component:
                continue

            if count:
                print_util.append_lines(delimiter, wrap, lines)
            count += 1
            # Make multiline components a separate block on a new line, unless
            # we already are on a new line.
            if (newline or len(print_component) > 1) and lines and lines[-1]:
                lines += print_component
            else:
                print_util.append_lines(print_component, wrap, lines)

            newline = len(print_component) > 1

        if not count:
            print_util.append_lines(["<no components>"], wrap, lines)

        # Indent everything apart from the first line.
        return [lines[0]] + map(lambda x: '  ' + x, lines[1:])

class SequenceAndSetBaseType(univ.SequenceAndSetBase, ConstructedBaseType):
    def label(self, idx):
        """String label of the |idx|^th component"""
        return self.getNameByPosition(idx)

class Sequence(univ.Sequence, SequenceAndSetBaseType):
    pass

class SequenceOf(univ.SequenceOf, ConstructedBaseType):
    pass

class Set(univ.Set, SequenceAndSetBaseType):
    pass

class SetOf(univ.SetOf, ConstructedBaseType):
    pass

class Choice(univ.Choice, SequenceAndSetBaseType):
    # There is only ever one component anyway
    PRINT_DELIMITER = ''
    def components(self):
        """Get the components of the Choice object. Since the object can have
        at most one component set, this yields at most one value.
        Yields:
            a (name, value) tuple with the name and value of the component,
            if one is set."""
        try:
            yield (self.getName(), self.getComponent())
        except pyasn1_error.PyAsn1Error:
            pass
