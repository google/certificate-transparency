import copy

from ct.crypto.asn1 import x509_name


# This class is in a partial refactor state, see also
# https://code.google.com/p/certificate-transparency/issues/detail?id=13
# https://code.google.com/p/certificate-transparency/issues/detail?id=12
class GeneralName(object):
    """Class to represent a parsed X509 GeneralName"""
    def __init__(self, asn1_general_name):
        self._asn1_name = asn1_general_name
        self._parse_name()

    def _parse_name(self):
        # Each GeneralName has only one component, being a CHOICE.
        self._type = self._asn1_name.component_key()
        self._parse_name_value(self._asn1_name.component_value())

    def _parse_name_value(self, name_value):
        # TODO(ekasper) to figure out appropriate encodings for each type.
        if self._type in [x509_name.DNS_NAME, x509_name.RFC822_NAME,
                          x509_name.URI_NAME]:
            self._value = name_value.value
        elif self._type == x509_name.DIRECTORY_NAME:
            rdn_sequence = name_value
            values_array = []
            # For directoryName, the value is a list of pairs, each pair
            # containing a part of the RDN and it's value, e.g.:
            # [('O', 'this'), ('OU', 'that')]
            for (cidx, cvalue) in rdn_sequence.iteritems():
                # FIXME(ekasper): this appears wrong as it's only considering
                # the first component of each set.
                type_and_value = cvalue[0]
                rdn_type = str(type_and_value["type"])
                v = type_and_value["value"]
                # These are ANY DEFINED BY so we may or may not have decoded
                # them. For all currently recognized types, the decoded value is
                # a DirectoryString, so .component_value() gives us the
                # underlying string value.
                # TODO(ekasper): in order to avoid future breakage, move this to
                # the Name class.
                if v.decoded:
                    rdn_value = v.decoded_value.component_value()
                else:
                    rdn_value = v.value
                values_array.append((rdn_type, rdn_value))
            self._value = values_array
        elif self._type == x509_name.IP_ADDRESS_NAME:
            self._value = tuple([ord(x) for x in name_value.value])
        elif self._type == x509_name.OTHER_NAME:
            # for otherName, the value is (oid, oid_octets)
            type_id  = name_value["type-id"].value
            type_value = name_value["value"].value
            self._value = (type_id, type_value)
        else:
            # This case covers: x400Address, ediPartyName, registeredID
            self._value = None

    def type(self):
        """Indicates the type of the GeneralName.
        Returns:
            A string representing the type of the name, such as dNSName.
        """
        return self._type

    def value(self):
        """Returns the value of this GeneralName.

        Note that as the value depends on the type, the returned value differs
        based on the type. For dNSName, rfc822Name, uniformResourceIdentifier
        and iPAddress, that would be a string.
        For directoryName, that would be a list with pairs of attribute, value.
        For otherName that would be a pair of (oid, oid_octets)
        For everything else, it'd be None.
        """
        return self._value

    def as_asn1(self):
        """Returns a copy of the ASN1 object representing this GeneralName."""
        # Temporary hack to keep backwards compatibility. We'll expose the
        # structure directly (without copying) once the refactor is complete.
        return copy.deepcopy(self._asn1_name)

    def __str__(self):
        return self._type + ":" + str(self._value)


def parse_alternative_names(asn1_alternative_names_extension):
    """Parses the ASN1 representation of Subject Alternative Names extension.
    Args:
        asn1_alternative_names_extension: The ASN1 component for the extension.
    Returns:
        A list of GeneralName instances.
    """

    return [GeneralName(n) for n in asn1_alternative_names_extension]
