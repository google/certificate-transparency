from ct.crypto.asn1 import x509_name
from pyasn1 import error as pyasn1_error


class GeneralName(object):
    """Class to represent a parsed X509 GeneralName"""
    def __init__(self, asn1_general_name):
        self.__asn1_name = asn1_general_name
        self.__parse_name()

    def __parse_name(self):
        # Each GeneralName has only one component, being a CHOICE.
        self.__type = self.__asn1_name.getName()
        self.__parse_name_value(self.__asn1_name.getComponent())

    def __parse_name_value(self, name_value):
        # TODO(ekasper) to figure out appropriate encodings for each type.
        if self.__type in [
            x509_name.DNS_NAME, x509_name.RFC822_NAME, x509_name.URI_NAME]:
            try:
                self.__value = name_value.asOctets()
            except pyasn1_error.PyAsn1Error:
                self.__value = ""
        elif self.__type == x509_name.DIRECTORY_NAME:
            rdn_sequence = name_value.getComponentByPosition(0)
            values_array = []
            # For directoryName, the value is a list of pairs, each pair
            # containing a part of the RDN and it's value, e.g.:
            # [('O', 'this'), ('OU', 'that')]
            for (cidx, cvalue) in rdn_sequence.components():
                type_and_value = cvalue.getComponentByPosition(0)
                rdn_type = (type_and_value.getComponentByPosition(0)
                    .string_value())
                rdn_value = type_and_value.getComponentByPosition(1).asOctets()
                values_array.append((rdn_type, rdn_value))
            self.__value = values_array
        elif self.__type == x509_name.IP_ADDRESS_NAME:
            try:
                self.__value = name_value.asNumbers()
            except pyasn1_error.PyAsn1Error:
                self.__value = ()
        elif self.__type == x509_name.OTHER_NAME:
            # for otherName, the value is (oid, oid_octets)
            try:
                type_id  = name_value.getComponentByName('type-id').oid()
                type_value = name_value.getComponentByName('value').asOctets()
                self.__value = (type_id, type_value)
            except pyasn1_error.PyAsn1Error:
                self.__value = (None, None)
        else:
            # This case covers: x400Address, ediPartyName, registeredID
            self.__value = None

    def type(self):
        """Indicates the type of the GeneralName.
        Returns:
            A string representing the type of the name, such as dNSName.
        """
        return self.__type

    def value(self):
        """Returns the value of this GeneralName.

        Note that as the value depends on the type, the returned value differs
        based on the type. For dNSName, rfc822Name, uniformResourceIdentifier
        and iPAddress, that would be a string.
        For directoryName, that would be a list with pairs of attribute, value.
        For otherName that would be a pair of (oid, oid_octets)
        For everything else, it'd be None.
        """
        return self.__value

    def as_asn1(self):
        """Returns a copy of the ASN1 object representing this GeneralName."""
        return self.__asn1_name.clone(cloneValueFlag=True)

    def __str__(self):
        return self.__type + ":" + str(self.__value)


def parse_alternative_names(asn1_alternative_names_extension):
    """Parses the ASN1 representation of Subject Alternative Names extension.
    Args:
        asn1_alternative_names_extension: The ASN1 component for the extension.
    Returns:
        A list of GeneralName instances.
    """

    return [GeneralName(n) for n in asn1_alternative_names_extension]
