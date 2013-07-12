import logging

from pyasn1.type import constraint, namedtype
from pyasn1 import error as pyasn1_error
from ct.crypto import error
from ct.crypto.asn1 import oid
from ct.crypto.asn1 import types

class AttributeValue(types.Any):
    pass

class AttributeType(oid.ObjectIdentifier):
    def value_type(self):
      """Return an ASN.1 type object corresponding to the attribute type."""
      try:
        return _ATTRIBUTE_VALUE_TYPE_DICT[self]
      except KeyError:
        raise error.UnknownASN1AttributeTypeError("Unknown attribute type: %s" %
                                                  self.human_readable())

class AttributeTypeAndValue(types.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('value', AttributeValue())
        )
    PRINT_LABELS = False
    # type=value, e.g., CN=google.com
    PRINT_DELIMITER = '='

    # It would be nice to handle context-specific nodes transparently at the
    # decoder layer but pyasn1 doesn't have an obvious plugin spot for custom
    # decoders. ANY values are stored as OctetStrings and the documentation
    # suggests they should be decoded at the application layer, so this is what
    # we do.
    def get_decoded_value(self, decode_fun):
        """Decode the ANY 'value' according to the decoded 'type' component.
        Args:
            decode_fun: the decoding function to use. The function should match
                        the pyasn1 decoder signature.
        Returns: an ASN1 element specified by 'type'.
        Raises:
            UnknownASN1AttributeTypeError: 'type' does not have a known
                                            value type
            ASN1Error: object is not a proper ASN.1 value object, or 'value' is
                       not a valid encoding of the anticipated type."""

        attr_type = self.getComponentByName('type')
        attr_value = self.getComponentByName('value')
        if attr_type is None or attr_value is None:
            raise error.ASN1Error("Attempting to decode an incomplete object %s"
                                  % self.human_readable())
        try:
            value_type = attr_type.value_type()
        except error.UnknownASN1AttributeTypeError:
            raise
        try:
            decoded_value, rest = decode_fun(attr_value,
                                             asn1Spec=value_type)
        except pyasn1_error.PyAsn1Error as e:
            raise error.ASN1Error("Unable to decode name attribute: %s" % e)
        else:
            if rest:
                # If there are leftover bytes here, then best not to trust the
                # result at all.
              raise error.ASN1Error("Invalid encoding of name attribute %s"
                                    % value_type.human_readable())
            else:
                return decoded_value

    def set_decoded_value(self, decode_fun):
        """Decode the ANY 'value' according to the decoded 'type' component
        and set the 'value' component to the decoded value. If the 'type'
        component doesn't have a known value type, the ANY value is kept.
        Args:
            decode_fun: the decoding function to use. The function should match
            the pyasn1 decoder signature.
        Raises:
            ASN1Error: 'value' has invalid encoding.
        """
        try:
            decoded_value = self.get_decoded_value(decode_fun)
        except error.UnknownASN1AttributeTypeError as e:
        # RFC 5280 does not restrict the set of attribute types, therefore we
        # do not raise here upon encountering an unknown type.
            logging.warning("Unable to decode attribute value: %s" % e)
        # However any other error is a real error and we let it raise.
        else:
            # Note: this does not break interpretation (since ANY is a supertype
            # of everything) nor re-encoding :)
            self.setComponentByName('value', value=decoded_value)

class RelativeDistinguishedName(types.SetOf):
    PRINT_LABELS=False
    PRINT_DELIMITER=','
    componentType = AttributeTypeAndValue()
    def set_decoded_values(self, decode_fun):
        """Attempt to set ANY attribute values to their decoded values.
        Args:
            decode_fun: the decoding function to use. The function should match
            the pyasn1 decoder signature.
        Raises:
            ASN1Error: a value encoding is invalid."""
        for attr in self:
            attr.set_decoded_value(decode_fun)

class RDNSequence(types.SequenceOf):
    PRINT_LABELS=False
    PRINT_DELIMITER='/'
    componentType = RelativeDistinguishedName()
    def set_decoded_values(self, decode_fun):
        """Attempt to set ANY attribute values in RDNs to their decoded values.
        Args:
            decode_fun: the decoding function to use. The function should match
            the pyasn1 decoder signature.
        Raises:
            ASN1Error: a value encoding is invalid."""
        for rdn in self:
            rdn.set_decoded_values(decode_fun)

class Name(types.Choice):
    PRINT_LABELS=False
    PRINT_DELIMITER=''
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('rdnSequence', RDNSequence())
        )
    def set_decoded_values(self, decode_fun):
        """Attempt to set ANY attribute values in RDNs to their decoded values.
        Args:
            decode_fun: the decoding function to use. The function should match
            the pyasn1 decoder signature.
        Raises:
            ASN1Error: a value encoding is invalid."""
        # Technically this component is a CHOICE, but only rdnSequence is
        # currently defined.
        rdn_sequence = self.getComponentByName('rdnSequence')
        rdn_sequence.set_decoded_values(decode_fun)

def _generate_directory_string_spec(minlen, maxlen):
    return namedtype.NamedTypes(
        namedtype.NamedType('teletexString', types.TeletexString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(minlen, maxlen))),
        namedtype.NamedType('printableString', types.PrintableString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(minlen, maxlen))),
        namedtype.NamedType('universalString', types.UniversalString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(minlen, maxlen))),
        namedtype.NamedType('utf8String', types.UTF8String().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(minlen, maxlen))),
        namedtype.NamedType('bmpString', types.BMPString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(minlen, maxlen)))
        )

# MAX indicates no upper bound, but pyasn1 doesn't have one-sided
# range constraints, so just make it something really big.
_MAX = 1 << 64

class DirectoryString(types.Choice):
    PRINT_LABELS = False
    componentType = _generate_directory_string_spec(1, _MAX)

_UB_NAME = types.Integer(32768)
class X520Name(DirectoryString):
    componentType = _generate_directory_string_spec(1, _UB_NAME)

_UB_COMMON_NAME = types.Integer(64)
# RFC 5280 says DirectoryName when DirectoryString is apparently meant
class X520CommonName(DirectoryString):
    componentType = _generate_directory_string_spec(1, _UB_COMMON_NAME)

_UB_LOCALITY_NAME = types.Integer(128)
class X520LocalityName(DirectoryString):
    componentType = _generate_directory_string_spec(1, _UB_LOCALITY_NAME)

_UB_STATE_NAME = types.Integer(128)
class X520StateOrProvinceName(DirectoryString):
    componentType = _generate_directory_string_spec(1, _UB_STATE_NAME)

_UB_ORGANIZATION_NAME = types.Integer(64)
class X520OrganizationName(DirectoryString):
    componentType = _generate_directory_string_spec(1, _UB_ORGANIZATION_NAME)

_UB_ORGANIZATIONAL_UNIT_NAME = types.Integer(64)
class X520OrganizationalUnitName(DirectoryString):
    componentType = _generate_directory_string_spec(1, _UB_ORGANIZATIONAL_UNIT_NAME)

_UB_TITLE = types.Integer(64)
class X520Title(DirectoryString):
  componentType = _generate_directory_string_spec(1, _UB_TITLE)

# The capitalization inconsistency hurts my eyes but is taken verbatim
# from the RFC.
class X520dnQualifier(types.PrintableString):
    # No size constraints are specified
    pass

class X520countryName(types.PrintableString):
    subtypeSpec = (types.PrintableString.subtypeSpec +
                   constraint.ValueSizeConstraint(2, 2))
    pass

_UB_SERIAL_NUMBER = types.Integer(64)
class X520SerialNumber(types.PrintableString):
    subtypeSpec = (types.PrintableString.subtypeSpec +
                   constraint.ValueSizeConstraint(1, _UB_SERIAL_NUMBER))
    pass

_UB_PSEUDONYM = types.Integer(128)
class X520Pseudonym(DirectoryString):
    componentType = _generate_directory_string_spec(1, _UB_PSEUDONYM)

class DomainComponent(types.IA5String):
    # No size constraints are specified
    pass

_UB_EMAILADDRESS_LENGTH = types.Integer(255)
class EmailAddress(types.IA5String):
    subtypeSpec = (types.IA5String.subtypeSpec +
                   constraint.ValueSizeConstraint(1, _UB_EMAILADDRESS_LENGTH))
    pass

# Create aliases
# This means you can do
#
# >>> import x509_name
# >>> x509_name.ID_AT_NAME.value_type()
# X520Name()
# >>> x509_name.ID_AT_NAME.long_name()
# 'id-at-name'
# >>> x509_name.ID_AT_NAME.human_readable()
# 'name'
#
# as well as
#
# >>> import oid
# >>> oid.ID_AT_NAME.human_readable()
# 'name'
#
# This, of course, won't work:
#
# >>> oid.ID_AT_NAME.value_type()
# AttributeError: ObjectIdentifier instance has no attribute 'value_type'
#
# but this does:
#
# import oid, x509_name
# >>> x509_name.ID_AT_NAME == oid.ID_AT_NAME
# True
#
ID_AT_NAME = AttributeType(oid.ID_AT_NAME)
ID_AT_SURNAME = AttributeType(oid.ID_AT_SURNAME)
ID_AT_GIVEN_NAME = AttributeType(oid.ID_AT_GIVEN_NAME)
ID_AT_INITIALS = AttributeType(oid.ID_AT_INITIALS)
ID_AT_GENERATION_QUALIFIER = AttributeType(oid.ID_AT_GENERATION_QUALIFIER)
ID_AT_COMMON_NAME =  AttributeType(oid.ID_AT_COMMON_NAME)
ID_AT_LOCALITY_NAME = AttributeType(oid.ID_AT_LOCALITY_NAME)
ID_AT_STATE_OR_PROVINCE_NAME = AttributeType(oid.ID_AT_STATE_OR_PROVINCE_NAME)
ID_AT_ORGANIZATION_NAME = AttributeType(oid.ID_AT_ORGANIZATION_NAME)
ID_AT_ORGANIZATIONAL_UNIT_NAME =  AttributeType(oid.ID_AT_ORGANIZATIONAL_UNIT_NAME)
ID_AT_TITLE = AttributeType(oid.ID_AT_TITLE)
ID_AT_DN_QUALIFIER = AttributeType(oid.ID_AT_DN_QUALIFIER)
ID_AT_COUNTRY_NAME = AttributeType(oid.ID_AT_COUNTRY_NAME)
ID_AT_SERIAL_NUMBER = AttributeType(oid.ID_AT_SERIAL_NUMBER)
ID_AT_PSEUDONYM = AttributeType(oid.ID_AT_PSEUDONYM)
ID_DOMAIN_COMPONENT = AttributeType(oid.ID_DOMAIN_COMPONENT)
ID_EMAIL_ADDRESS = AttributeType(oid.ID_EMAIL_ADDRESS)

_ATTRIBUTE_VALUE_TYPE_DICT = {
    ID_AT_NAME: X520Name(),
    ID_AT_SURNAME: X520Name(),
    ID_AT_GIVEN_NAME: X520Name(),
    ID_AT_INITIALS: X520Name(),
    ID_AT_GENERATION_QUALIFIER: X520Name(),
    ID_AT_COMMON_NAME: X520CommonName(),
    ID_AT_LOCALITY_NAME: X520LocalityName(),
    ID_AT_STATE_OR_PROVINCE_NAME: X520StateOrProvinceName(),
    ID_AT_ORGANIZATION_NAME: X520OrganizationName(),
    ID_AT_ORGANIZATIONAL_UNIT_NAME: X520OrganizationalUnitName(),
    ID_AT_TITLE: X520Title(),
    ID_AT_DN_QUALIFIER: X520dnQualifier(),
    ID_AT_COUNTRY_NAME: X520countryName(),
    ID_AT_SERIAL_NUMBER: X520SerialNumber(),
    ID_AT_PSEUDONYM: X520Pseudonym(),
    ID_DOMAIN_COMPONENT: DomainComponent(),
    ID_EMAIL_ADDRESS: EmailAddress(),
}
