"""ASN.1 object identifiers. This module contains a dictionary of known OIDs."""

import abc

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

# Standard X509v3 certificate extensions
ID_CE_AUTHORITY_KEY_IDENTIFIER = ObjectIdentifier("2.5.29.35")
ID_CE_SUBJECT_KEY_IDENTIFIER = ObjectIdentifier("2.5.29.14")
ID_CE_KEY_USAGE = ObjectIdentifier("2.5.29.15")
ID_CE_PRIVATE_KEY_USAGE_PERIOD = ObjectIdentifier("2.5.29.16")
ID_CE_CERTIFICATE_POLICIES = ObjectIdentifier("2.5.29.32")
ID_CE_SUBJECT_ALT_NAME = ObjectIdentifier("2.5.29.17")
ID_CE_ISSUER_ALT_NAME = ObjectIdentifier("2.5.29.18")
ID_CE_SUBJECT_DIRECTORY_ATTRIBUTES = ObjectIdentifier("2.5.29.9")
ID_CE_BASIC_CONSTRAINTS = ObjectIdentifier("2.5.29.19")
ID_CE_NAME_CONSTRAINTS = ObjectIdentifier("2.5.29.30")
ID_CE_POLICY_CONSTRAINTS = ObjectIdentifier("2.5.29.30")
ID_CE_EXT_KEY_USAGE = ObjectIdentifier("2.5.29.37")
ID_CE_CRL_DISTRIBUTION_POINTS = ObjectIdentifier("2.5.29.31")
ID_CE_INHIBIT_ANY_POLICY = ObjectIdentifier("2.5.29.54")
ID_PE_AUTHORITY_INFO_ACCESS = ObjectIdentifier("1.3.6.1.5.5.7.1.1")
ID_PE_SUBJECT_INFO_ACCESS = ObjectIdentifier("1.3.6.1.5.5.7.1.11")

# RFC 3280 - Used in ExtendedKeyUsage extension
ID_KP_SERVER_AUTH = ObjectIdentifier("1.3.6.1.5.5.7.3.1")
ID_KP_CLIENT_AUTH = ObjectIdentifier("1.3.6.1.5.5.7.3.2")
ID_KP_CODE_SIGNING = ObjectIdentifier("1.3.6.1.5.5.7.3.3")
ID_KP_EMAIL_PROTECTION = ObjectIdentifier("1.3.6.1.5.5.7.3.4")
ID_KP_TIME_STAMPING = ObjectIdentifier("1.3.6.1.5.5.7.3.8")
ID_KP_OCSP_SIGNING = ObjectIdentifier("1.3.6.1.5.5.7.3.9")

# RFC 3280 - Used in Authority Info Access extension
ID_OSCP = ObjectIdentifier("1.3.6.1.5.5.7.48.1")
ID_AD_CA_ISSUERS = ObjectIdentifier("1.3.6.1.5.5.7.48.2")

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
    ID_AT_POST_OFFICE_BOX: ("id-at-postOfficeBox", "postOfficeBox"),
    ID_CE_AUTHORITY_KEY_IDENTIFIER: ("id-ce-authorityKeyIdentifier",
                                     "authorityKeyIdentifier"),
    ID_CE_SUBJECT_KEY_IDENTIFIER: ("id-ce-subjectKeyIdentifier",
                                     "subjectKeyIdentifier"),
    ID_CE_KEY_USAGE: ("id-ce-keyUsage", "keyUsage"),
    ID_CE_PRIVATE_KEY_USAGE_PERIOD: ("id-ce-privateKeyUsagePeriod",
                                     "privateKeyUsagePeriod"),
    ID_CE_CERTIFICATE_POLICIES: ("id-ce-certificatePolicies",
                                 "certificatePolicies"),
    ID_CE_SUBJECT_ALT_NAME: ("id-ce-subjectAltName", "subjectAltName"),
    ID_CE_ISSUER_ALT_NAME: ("id-ce-issuerAltName", "issuerAltName"),
    ID_CE_SUBJECT_DIRECTORY_ATTRIBUTES: ("id-ce-subjectDirectoryAttributes",
                                         "subjectDirectoryAttributes"),
    ID_CE_BASIC_CONSTRAINTS: ("id-ce-basicConstraints", "basicConstraints"),
    ID_CE_NAME_CONSTRAINTS: ("id-ce-nameConstraints", "nameConstraints"),
    ID_CE_POLICY_CONSTRAINTS: ("id-ce-policyConstraints", "policyConstraints"),
    ID_CE_EXT_KEY_USAGE: ("id-ce-extKeyUsage", "extendedKeyUsage"),
    ID_CE_CRL_DISTRIBUTION_POINTS: ("id-ce-cRLDistributionPoints",
                                    "CRLDistributionPoints"),
    ID_CE_INHIBIT_ANY_POLICY: ("id-ce-inhibitAnyPolicy", "inhibitAnyPolicy"),
    ID_PE_AUTHORITY_INFO_ACCESS: ("id-pe-authorityInfoAccess",
                                  "authorityInformationAccess"),
    ID_PE_SUBJECT_INFO_ACCESS: ("id-pe-subjectInfoAccess",
                                  "subjectInformationAccess"),

    ID_KP_SERVER_AUTH: ("id-kp-serverAuth", "serverAuth"),
    ID_KP_CLIENT_AUTH: ("id-kp-clientAuth", "clientAuth"),
    ID_KP_CODE_SIGNING: ("id-kp-codeSigning", "codeSigning"),
    ID_KP_EMAIL_PROTECTION: ("id-kp-emailProtection", "emailProtection"),
    ID_KP_TIME_STAMPING: ("id-kp-timeStamping", "timeStamping"),
    ID_KP_OCSP_SIGNING: ("id-kp-OCSPSigning", "OCSPSigning"),

    ID_OSCP: ("id-oscp", "OSCP"),
    ID_AD_CA_ISSUERS: ("id-ad-caIssuers", "caIssuers")

    }

class ValueTypeIdentifier(ObjectIdentifier):
    """An OID that identifies an ASN.1 structure."""
    @abc.abstractmethod
    def value_type(self):
        """Return an ASN.1 type corresponding to the OID.
        Returns: an ASN.1 type.
        Raises:  ct.crypto.error.UnknownASN1TypeError.
        """
        pass

class DecodableAny(types.Any):
    """An ANY ASN.1 object whose encoding/decoding is determined by a
    corresponding ValueTypeIdentifier OID."""
    def get_decoded_value(self, value_type_oid, decode_fun,
                          default_value_type=None):
        """Get the decoded ASN.1 object.
        Args:
            value_type_oid: the ValueTypeIdentifier object that determines the
                            ASN.1 type.
            decode_fun    : the decoding function to use
            default_value_type: the default type to fall back to in case
                                value_type_oid does not point to a known type.
        """
        unknown_error = None
        try:
            value_type = value_type_oid.value_type()
        except error.UnknownASN1TypeError as e:
            if default_value_type is None:
                raise e
            # Save the error but see if the unknown type can be decoded as the
            # default value type. If decoding still fails, then we re-raise this
            # this error to indicate we don't know how to decode the attribute.
            # decode the attribute.
            unknown_error = e
            value_type = default_value_type
 
        try:
            decoded_value, rest = decode_fun(self, asn1Spec=value_type())
        except pyasn1_error.PyAsn1Error as e:
            if unknown_error:
                raise unknown_error
            else:
                raise error.ASN1Error("Unable to decode %s value:\n%s" %
                                      (value_type, e))
        else:
            if rest:
                # If there are leftover bytes here, then best not to trust the
                # result at all.
                if unknown_error:
                    raise unknown_error
                else:
                    raise error.ASN1Error("Invalid encoding of %s" % value_type)
            else:
                return decoded_value
