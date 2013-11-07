"""ASN.1 specification for X509 name types."""

from ct.crypto.my_asn1 import oid
from ct.crypto.my_asn1 import types


class AttributeType(oid.ObjectIdentifier):
    pass


class AttributeValue(types.Any):
    pass


class DirectoryString(types.Choice):
    components = {
        "teletexString": types.TeletexString,
        "printableString": types.PrintableString,
        "universalString": types.UniversalString,
        "utf8String": types.UTF8String,
        "bmpString": types.BMPString,
        # Does not really belong here.
        "ia5String": types.IA5String
        }


_ATTRIBUTE_DICT = {
    # Note: this mapping does not conform to the RFCs, as some of the OIDs
    # have more restricted values. But real certificates do not conform either,
    # so we try to be lenient and accept all strings that we can recognize.
    oid.ID_AT_NAME: DirectoryString,
    oid.ID_AT_SURNAME: DirectoryString,
    oid.ID_AT_GIVEN_NAME: DirectoryString,
    oid.ID_AT_INITIALS: DirectoryString,
    oid.ID_AT_GENERATION_QUALIFIER: DirectoryString,
    oid.ID_AT_COMMON_NAME: DirectoryString,
    oid.ID_AT_LOCALITY_NAME: DirectoryString,
    oid.ID_AT_STATE_OR_PROVINCE_NAME: DirectoryString,
    oid.ID_AT_ORGANIZATION_NAME: DirectoryString,
    oid.ID_AT_ORGANIZATIONAL_UNIT_NAME: DirectoryString,
    oid.ID_AT_TITLE: DirectoryString,
    oid.ID_AT_DN_QUALIFIER: DirectoryString,  # PrintableString
    oid.ID_AT_COUNTRY_NAME: DirectoryString,  # PrintableString
    oid.ID_AT_SERIAL_NUMBER: DirectoryString,  # PrintableString
    oid.ID_AT_PSEUDONYM: DirectoryString,
    oid.ID_DOMAIN_COMPONENT: DirectoryString,  # IA5String
    oid.ID_EMAIL_ADDRESS: DirectoryString,  # IA5String
    oid.ID_AT_STREET_ADDRESS: DirectoryString,
    oid.ID_AT_DESCRIPTION: DirectoryString,
    oid.ID_AT_BUSINESS_CATEGORY: DirectoryString,
    oid.ID_AT_POSTAL_CODE: DirectoryString,
    oid.ID_AT_POST_OFFICE_BOX: DirectoryString,
    }


class AttributeTypeAndValue(types.Sequence):
    print_labels = False
    print_delimiter = "="
    components = (
        (types.Component("type", AttributeType)),
        (types.Component("value", AttributeValue, defined_by="type",
                         lookup=_ATTRIBUTE_DICT))
        )


class RelativeDistinguishedName(types.SetOf):
    print_labels = False
    print_delimiter = ", "
    component = AttributeTypeAndValue


class RDNSequence(types.SequenceOf):
    print_labels = False
    print_delimiter = "/"
    component = RelativeDistinguishedName


# Bypass the CHOICE indirection since exactly one option is specified.
# class Name(types.Choice):
#     components = {"rdnSequence": RDNSequence}
class Name(RDNSequence):
    pass


class OtherName(types.Sequence):
    print_delimiter = ", "
    components = (
        (types.Component("type-id", oid.ObjectIdentifier)),
        (types.Component("value", types.Any.explicit(0)))
        )


class EDIPartyName(types.Sequence):
    print_delimiter = ", "
    components = (
        # Definition here: http://tools.ietf.org/html/rfc5280#section-4.2.1.6
        # Note: this definition suggests that the tagging is implicit.
        # However, implicit tagging of a CHOICE type is ambiguous, so this is
        # in practice interpreted as an explicit tag.
        (types.Component("nameAssigner", DirectoryString.explicit(0),
                         optional=True)),
        (types.Component("partyName", DirectoryString.explicit(1)))
        )


# Partially defined ORAddress: we've not come across any certs that contain it
# but this should be enough to allow the decoder to continue without blowing up.
class BuiltInDomainDefinedAttributes(types.SequenceOf):
    component = types.Any


class ExtensionAttributes(types.SetOf):
    component = types.Any


class ORAddress(types.Sequence):
    components = (
        (types.Component("builtInStandardAttributes", types.Any)),
        (types.Component("builtInDomainDefinedAttributes",
                         BuiltInDomainDefinedAttributes, optional=True)),
        (types.Component("extensionAttributes",
                         ExtensionAttributes, optional=True))
        )


class GeneralName(types.Choice):
    # Definition here: http://tools.ietf.org/html/rfc5280#section-4.2.1.6
    components = {
        "otherName": OtherName.implicit(0),
        "rfc822Name": types.IA5String.implicit(1),
        "dnsName": types.IA5String.implicit(2),
        "x400Address": ORAddress.implicit(3),
        # Implicit CHOICE tag is converted to an explicit one.
        "directoryName": Name.explicit(4),
        "ediPartyName": EDIPartyName.implicit(5),
        "uniformResourceIdentiifer": types.IA5String.implicit(6),
        "iPAddress": types.OctetString.implicit(7),
        "registeredID": oid.ObjectIdentifier.implicit(8)
        }
