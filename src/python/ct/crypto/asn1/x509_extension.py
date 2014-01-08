"""ASN.1 specification for X509 extensions."""

from ct.crypto.asn1 import named_value
from ct.crypto.asn1 import oid
from ct.crypto.asn1 import tag
from ct.crypto.asn1 import types
from ct.crypto.asn1 import x509_common
from ct.crypto.asn1 import x509_name


# Standard extensions from RFC 5280.
class BasicConstraints(types.Sequence):
    print_delimiter = ", "
    components = (
        (types.Component("cA", types.Boolean, default=False)),
        (types.Component("pathLenConstraint", types.Integer, optional=True))
        )


class SubjectAlternativeNames(types.SequenceOf):
    print_delimiter = ", "
    component = x509_name.GeneralName


class KeyUsage(types.NamedBitList):
    DIGITAL_SIGNATURE = named_value.NamedValue("digitalSignature", 0)
    NON_REPUDIATION = named_value.NamedValue("nonRepudiation", 1)
    KEY_ENCIPHERMENT = named_value.NamedValue("keyEncipherment", 2)
    DATA_ENCIPHERMENT = named_value.NamedValue("dataEncipherment", 3)
    KEY_AGREEMENT = named_value.NamedValue("keyAgreement", 4)
    KEY_CERT_SIGN = named_value.NamedValue("keyCertSign", 5)
    CRL_SIGN = named_value.NamedValue("cRLSign", 6)
    ENCIPHER_ONLY = named_value.NamedValue("encipherOnly", 7)
    DECIPHER_ONLY = named_value.NamedValue("decipherOnly", 8)
    named_bit_list = (DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT,
                      DATA_ENCIPHERMENT, KEY_AGREEMENT, KEY_CERT_SIGN,
                      CRL_SIGN, ENCIPHER_ONLY, DECIPHER_ONLY)


class KeyPurposeID(oid.ObjectIdentifier):
    pass


class ExtendedKeyUsage(types.SequenceOf):
    print_delimiter = ", "
    print_labels = False
    component = KeyPurposeID


class KeyIdentifier(types.OctetString):
  pass


class SubjectKeyIdentifier(KeyIdentifier):
  pass


KEY_IDENTIFIER = "keyIdentifier"
AUTHORITY_CERT_ISSUER = "authorityCertIssuer"
AUTHORITY_CERT_SERIAL_NUMBER = "authorityCertSerialNumber"


class AuthorityKeyIdentifier(types.Sequence):
  components = (
      types.Component(KEY_IDENTIFIER, KeyIdentifier.implicit(0), optional=True),
      types.Component(AUTHORITY_CERT_ISSUER, x509_name.GeneralNames.implicit(1),
                      optional=True),
      types.Component(AUTHORITY_CERT_SERIAL_NUMBER,
                      x509_common.CertificateSerialNumber.implicit(2),
                      optional=True)
      )


class DisplayText(types.Choice):
    components = {
        "ia5String": types.IA5String,
        "visibleString": types.VisibleString,
        "bmpString": types.BMPString,
        "utf8String": types.UTF8String
        }


class NoticeNumbers(types.SequenceOf):
    component = types.Integer


class NoticeReference(types.Sequence):
    components = (
        types.Component("organization", DisplayText),
        types.Component("noticeNumbers", NoticeNumbers)
        )


class UserNotice(types.Sequence):
    components = (
        types.Component("noticeRef", NoticeReference, optional=True),
        types.Component("explicitText", DisplayText, optional=True)
)



class CPSuri(types.IA5String):
    pass


_POLICY_QUALIFIER_DICT = {
    oid.ID_QT_CPS: CPSuri,
    oid.ID_QT_UNOTICE: UserNotice
}


POLICY_QUALIFIER_ID = "policyQualifierId"
QUALIFIER = "qualifier"


class PolicyQualifierInfo(types.Sequence):
    print_labels = False
    print_delimiter = ": "
    components = (
        types.Component(POLICY_QUALIFIER_ID, oid.ObjectIdentifier),
        types.Component(QUALIFIER, types.Any, defined_by="policyQualifierId",
                        lookup=_POLICY_QUALIFIER_DICT)
        )


class PolicyQualifiers(types.SequenceOf):
    print_labels = False
    component = PolicyQualifierInfo


POLICY_IDENTIFIER = "policyIdentifier"
POLICY_QUALIFIERS = "policyQualifiers"


class PolicyInformation(types.Sequence):
    components = (
        types.Component(POLICY_IDENTIFIER, oid.ObjectIdentifier),
        types.Component(POLICY_QUALIFIERS, PolicyQualifiers, optional=True)
)

class CertificatePolicies(types.SequenceOf):
    component = PolicyInformation


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
    oid.ID_CE_KEY_USAGE: KeyUsage,
    oid.ID_CE_EXT_KEY_USAGE: ExtendedKeyUsage,
    oid.ID_CE_SUBJECT_KEY_IDENTIFIER: SubjectKeyIdentifier,
    oid.ID_CE_AUTHORITY_KEY_IDENTIFIER: AuthorityKeyIdentifier,
    oid.ID_CE_CERTIFICATE_POLICIES: CertificatePolicies
    }


class Extension(types.Sequence):
    print_delimiter = ", "
    components = (
        types.Component("extnID", oid.ObjectIdentifier),
        types.Component("critical", types.Boolean, default=False),
        types.Component("extnValue", ExtensionValue, defined_by="extnID",
                         lookup=_EXTENSION_DICT)
        )


class Extensions(types.SequenceOf):
    component = Extension
