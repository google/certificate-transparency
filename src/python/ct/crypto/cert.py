from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1 import error as pyasn1_error

import logging
from ct.crypto import error, pem
from ct.crypto.asn1 import oid, x509, x509_name

class Certificate(object):
    _PEM_MARKERS = ("CERTIFICATE",)
    _ASN1_SPEC = x509.Certificate()
    def __init__(self, der_string):
        """Initialize from a DER string
        Args:
            der_string: a binary string containing the DER-encoded
            certificate."""
        self.__asn1_cert = Certificate.__decode_der(der_string)
        # Certs are primarily used as read-only objects so we cache the DER
        # encoding. If any public setters or other methods modifying the
        # contents of the certificate are ever added to this class, they must
        # invalidate the cached encoding.
        self.__cached_der = der_string

    def __repr__(self):
        # This prints the full ASN1 representation. Useful for debugging.
        return self.__asn1_cert.prettyPrint()

    def __str__(self):
        return self.__asn1_cert.human_readable(label=self.__class__.__name__)

    @classmethod
    def from_pem(cls, pem_string):
        """Read a single PEM-encoded certificate from a string.
        Args:
            pem_string: the certificate string
        Returns:
            a Certificate object
        Raises:
            ct.crypto.pem.PemError, ct.crypto.error.EncodingError: the string
            does not contain a valid PEM certificate"""
        der_cert, _ = pem.from_pem(pem_string, cls._PEM_MARKERS)
        return cls.from_der(der_cert)

    @classmethod
    def __decode_der(cls, der_string):
        try:
            asn1cert, rest = der_decoder.decode(
                der_string, asn1Spec=cls._ASN1_SPEC)
        except pyasn1_error.PyAsn1Error as e:
            raise error.ASN1Error("Invalid DER encoding: %s" % e)
        if rest:
            logging.warning("Ignoring extra bytes after certificate")

        # Decode subject and issuer names in-place.
        asn1cert.getComponentByName('tbsCertificate').getComponentByName(
            'subject').set_decoded_values(der_decoder.decode)
        asn1cert.getComponentByName('tbsCertificate').getComponentByName(
            'issuer').set_decoded_values(der_decoder.decode)
        return asn1cert

    @classmethod
    def from_der(cls, der_string):
        """Read a single DER-encoded certificate from a string.
        This is just an alias to __init__ to match from_pem().
        Args:
            der_string: the certificate string
        Returns:
            a Certificate object
        Raises:
            ct.crypto.error.ASN1Error: the string does not contain a valid
            DER certificate"""
        return cls(der_string)

    @classmethod
    def from_pem_file(cls, pem_file):
        """Read a single PEM-encoded certificate from a file.
        Args:
            pem_file: the certificate file
        Returns:
            a Certificate object
        Raises:
            ct.crypto.pem.PemError, ct.crypto.EncodingError: the file does not
            contain a valid PEM certificate
            IOError: the file could not be read"""
        der_cert, _ = pem.from_pem_file(pem_file, cls._PEM_MARKERS)
        return cls.from_der(der_cert)

    @classmethod
    def from_der_file(cls, der_file):
        """Read a single DER-encoded certificate from a file.
        Args:
            der_file: the certificate file
        Returns:
            a Certificate object
        Raises:
            ct.crypto.EncodingError: the file does not contain a valid DER
            certificate
            IOError: the file could not be read"""
        with open(der_file, 'rb') as f:
            return cls.from_der(f.read())

    def to_der(self):
        """Get the DER-encoding of the certificate."""
        # Currently the cached encoding is never invalidated.
        return self.__cached_der

    def subject_common_name(self):
        """Get the common name of the subject."""
        ret = ""
        rdn_sequence = (self.__asn1_cert.
                        getComponentByName('tbsCertificate').
                        getComponentByName('subject').
                        getComponentByName('rdnSequence'))
        for r in rdn_sequence:
            for attr in r:
                if (attr.getComponentByName('type') ==
                    x509_name.ID_AT_COMMON_NAME):
                    # A certificate should only have one common name.
                    # If it has multiple CNs, we take the last one to be
                    # the most specific.
                    # Use string_value() rather than human readable() to get
                    # just the value without any additional formatting.
                    ret = (attr.getComponentByName('value').getComponent().
                           string_value())
        return ret

    def subject_name(self):
        """Get a human readable string of the subject name attributes."""
        return (self.__asn1_cert.getComponentByName('tbsCertificate').
                getComponentByName('subject').human_readable(wrap=0))

    def issuer_name(self):
        """Get a human readable string of the issuer name attributes."""
        return (self.__asn1_cert.getComponentByName('tbsCertificate').
                getComponentByName('issuer').human_readable(wrap=0))
