"""ASN.1 object identifiers. This module contains a dictionary of known OIDs."""

from pyasn1.type import univ
from pyasn1 import error as pyasn1_error

from ct.crypto import error
from ct.crypto.asn1 import types

class ObjectIdentifier(univ.ObjectIdentifier, types.SimpleBaseType):
    def oid(self):
        """String representation of the numerical OID."""
        try:
            return str(self)
        except pyasn1_error.PyAsn1Error:
            return "<no value>"

    def short_name(self):
        """Return the short name representation of an OID, if one exists,
        or a string representation otherwise."""
        try:
            return _OID_NAME_DICT[self][1]
        except KeyError:
            # fall back to OID
            return self.oid()

    def long_name(self):
        """Return the long name representation of an OID, if one exists,
        or a string representation otherwise."""
        try:
            return _OID_NAME_DICT[self][0]
        except KeyError:
            return self.oid()

    def string_value(self):
        return self.short_name()

# Signature and public key algorithms
# RFC 3279
RSA_ENCRYPTION = ObjectIdentifier("1.2.840.113549.1.1.1")
MD2_WITH_RSA_ENCRYPTION = ObjectIdentifier("1.2.840.113549.1.1.2")
MD5_WITH_RSA_ENCRYPTION = ObjectIdentifier("1.2.840.113549.1.1.4")
SHA1_WITH_RSA_ENCRYPTION = ObjectIdentifier("1.2.840.113549.1.1.5")
ID_DSA = ObjectIdentifier("1.2.840.10040.4.1")
ID_DSA_WITH_SHA1 = ObjectIdentifier("1.2.840.10040.4.3")
ID_EC_PUBLICKEY = ObjectIdentifier("1.2.840.10045.2.1")
ECDSA_WITH_SHA1 = ObjectIdentifier("1.2.840.10045.4.1")
# RFC4055
ID_RSASSA_PSS = ObjectIdentifier("1.2.840.113549.1.1.10")
# RFC 4491
ID_GOSTR3411_94_WITH_GOSTR3410_94 = ObjectIdentifier("1.2.643.2.2.4")
ID_GOSTR3411_94_WITH_GOSTR3410_2001 = ObjectIdentifier("1.2.643.2.2.3")

# Naming attributes (RFC 5280)
ID_AT_NAME = ObjectIdentifier("2.5.4.41")
ID_AT_SURNAME = ObjectIdentifier("2.5.4.4")
ID_AT_GIVEN_NAME = ObjectIdentifier("2.5.4.42")
ID_AT_INITIALS = ObjectIdentifier("2.5.4.43")
ID_AT_GENERATION_QUALIFIER = ObjectIdentifier("2.5.4.44")
ID_AT_COMMON_NAME = ObjectIdentifier("2.5.4.3")
ID_AT_LOCALITY_NAME = ObjectIdentifier("2.5.4.7")
ID_AT_STATE_OR_PROVINCE_NAME = ObjectIdentifier("2.5.4.8")
ID_AT_ORGANIZATION_NAME = ObjectIdentifier("2.5.4.10")
ID_AT_ORGANIZATIONAL_UNIT_NAME = ObjectIdentifier("2.5.4.11")
ID_AT_TITLE = ObjectIdentifier("2.5.4.12")
ID_AT_DN_QUALIFIER = ObjectIdentifier("2.5.4.46")
ID_AT_COUNTRY_NAME = ObjectIdentifier("2.5.4.6")
ID_AT_SERIAL_NUMBER = ObjectIdentifier("2.5.4.5")
ID_AT_PSEUDONYM = ObjectIdentifier("2.5.4.65")
ID_DOMAIN_COMPONENT = ObjectIdentifier("0.9.2342.19200300.100.1.25")
ID_EMAIL_ADDRESS = ObjectIdentifier("1.2.840.113549.1.9.1")

# Other naming attributes commonly found in certs
ID_AT_STREET_ADDRESS = ObjectIdentifier("2.5.4.9")
ID_AT_DESCRIPTION = ObjectIdentifier("2.5.4.13")
ID_AT_BUSINESS_CATEGORY = ObjectIdentifier("2.5.4.15")
ID_AT_POSTAL_CODE = ObjectIdentifier("2.5.4.17")
ID_AT_POST_OFFICE_BOX = ObjectIdentifier("2.5.4.18")

_OID_NAME_DICT = {
    # Object identifier long names taken verbatim from the RFCs.
    # Short names are colloquial.
    RSA_ENCRYPTION: ("rsaEncryption", "RSA"),
    MD2_WITH_RSA_ENCRYPTION: ("md2WithRSAEncryption", "RSA-MD2"),
    MD5_WITH_RSA_ENCRYPTION: ("md5WithRSAEncryption", "RSA-MD5"),
    SHA1_WITH_RSA_ENCRYPTION: ("sha-1WithRSAEncryption", "RSA-SHA1"),
    ID_DSA: ("id-dsa", "DSA"),
    ID_DSA_WITH_SHA1: ("id-dsa-with-sha1", "DSA-SHA1"),
    ID_EC_PUBLICKEY: ("id-ecPublicKey", "EC-PUBKEY"),
    ECDSA_WITH_SHA1: ("ecdsa-with-SHA1", "ECDSA-SHA1"),
    ID_RSASSA_PSS: ("id-RSASSA-PSS", "RSASSA-PSS"),
    ID_GOSTR3411_94_WITH_GOSTR3410_94: ("id-GostR3411-94-with-GostR3410-94",
                                        "GOST94"),
    ID_GOSTR3411_94_WITH_GOSTR3410_2001: ("id-GostR3411-94-with-GostR3410-2001",
                                          "GOST2001"),
    ID_AT_NAME: ("id-at-name", "name"),
    ID_AT_SURNAME: ("id-at-surname", "surname"),
    ID_AT_GIVEN_NAME: ("id-at-givenName", "givenName"),
    ID_AT_INITIALS: ("id-at-initials", "initials"),
    ID_AT_GENERATION_QUALIFIER: ("id-at-generationQualifier", "genQualifier"),
    ID_AT_COMMON_NAME: ("id-at-commonName", "CN"),
    ID_AT_LOCALITY_NAME: ("id-at-localityName", "L"),
    ID_AT_STATE_OR_PROVINCE_NAME: ("id-at-stateOrProvinceName", "ST"),
    ID_AT_ORGANIZATION_NAME: ("id-at-organizationName", "O"),
    ID_AT_ORGANIZATIONAL_UNIT_NAME: ("id-at-organizationalUnitName", "OU"),
    ID_AT_TITLE: ("id-at-title", "title"),
    ID_AT_DN_QUALIFIER: ("id-at-dnQualifier", "dnQualifier"),
    ID_AT_COUNTRY_NAME: ("id-at-countryName", "C"),
    ID_AT_SERIAL_NUMBER: ("id-at-serialNumber", "serialNumber"),
    ID_AT_PSEUDONYM: ("id-at-pseudonym", "pseudonym"),
    ID_DOMAIN_COMPONENT: ("id-domainComponent", "domainComponent"),
    ID_EMAIL_ADDRESS: ("id-emailAddress", "email"),
    ID_AT_STREET_ADDRESS: ("id-at-streetAddress", "streetAddress"),
    ID_AT_DESCRIPTION: ("id-at-description", "description"),
    ID_AT_BUSINESS_CATEGORY: ("id-at-businessCategory", "businessCategory"),
    ID_AT_POSTAL_CODE: ("id-at-postalCode", "postalCode"),
    ID_AT_POST_OFFICE_BOX: ("id-at-postOfficeBox", "postOfficeBox")
    }
