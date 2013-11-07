"""ASN.1 specification for X509 extensions."""

from ct.crypto.my_asn1 import oid
from ct.crypto.my_asn1 import tag
from ct.crypto.my_asn1 import types
from ct.crypto.my_asn1 import x509_name


class BasicConstraints(types.Sequence):
    print_delimiter = ", "
    components = (
        (types.Component("cA", types.Boolean, default=False)),
        (types.Component("pathLenConstraint", types.Integer, optional=True))
        )


class SubjectAlternativeNames(types.SequenceOf):
    print_delimiter = ", "
    component = x509_name.GeneralName


# Hack! This is not a valid ASN.1 definition but it works: an extension value
# value is defined as a DER-encoded value wrapped in an OctetString.
# This is functionally equivalent to an Any type that is tagged with the
# OctetString tag.
@types.Universal(4, tag.PRIMITIVE)
class ExtensionValue(types.Any):
    pass


_EXTENSION_DICT = {
    oid.ID_CE_BASIC_CONSTRAINTS: BasicConstraints,
    oid.ID_CE_SUBJECT_ALT_NAME: SubjectAlternativeNames,
    }


class Extension(types.Sequence):
    print_delimiter = ", "
    components = (
        (types.Component("extnID", oid.ObjectIdentifier)),
        (types.Component("critical", types.Boolean, default=False)),
        (types.Component("extnValue", ExtensionValue, defined_by="extnID",
                         lookup=_EXTENSION_DICT))
        )


class Extensions(types.SequenceOf):
    component = Extension
