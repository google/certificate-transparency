import logging
import time

from ct.crypto import error
from ct.crypto import pem
from ct.crypto.asn1 import oid
from ct.crypto.asn1 import x509
from ct.crypto.asn1 import x509_extension
from ct.crypto.asn1 import x509_name

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1 import error as pyasn1_error


class Certificate(object):
    PEM_MARKERS = ("CERTIFICATE",)
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
        self.__cache_expiry()
        # id -> (critical, decoded_value)
        self.__cached_extensions = {}
        self.__cache_extensions()

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
            ct.crypto.pem.PemError, ct.crypto.error.ASN1Error: the string
            does not contain a valid PEM certificate"""
        der_cert, _ = pem.from_pem(pem_string, cls.PEM_MARKERS)
        return cls.from_der(der_cert)

    def __cache_expiry(self):
        # Let ASN1 errors raise through.
        self.__not_before = (
            self.__asn1_cert.getComponentByName("tbsCertificate").
            getComponentByName("validity").
            getComponentByName("notBefore").getComponent().gmtime())
        self.__not_after = (
            self.__asn1_cert.getComponentByName("tbsCertificate").
            getComponentByName("validity").
            getComponentByName("notAfter").getComponent().gmtime())

    def __cache_extensions(self):
        extensions = (self.__asn1_cert.getComponentByName("tbsCertificate").
                      getComponentByName("extensions"))
        for ext in extensions:
            try:
                extn_value = ext.get_decoded_value()
            except error.UnknownASN1TypeError:
                extn_value = ext.getComponentByName("extnValue")

            extn_id = ext.getComponentByName("extnID")
            if extn_id in self.__cached_extensions:
                raise error.ASN1Error("Duplicate extension %s: " %
                                      extn_id.string_value())

            self.__cached_extensions[extn_id] = (
                (ext.getComponentByName("critical"), extn_value))

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
        asn1cert.getComponentByName("tbsCertificate").getComponentByName(
            "subject").set_decoded_values(der_decoder.decode)
        asn1cert.getComponentByName("tbsCertificate").getComponentByName(
            "issuer").set_decoded_values(der_decoder.decode)
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
            ct.crypto.pem.PemError, ct.crypto.error.ASN1Error: the file does not
            contain a valid PEM certificate
            IOError: the file could not be read"""
        der_cert, _ = pem.from_pem_file(pem_file, cls.PEM_MARKERS)
        return cls.from_der(der_cert)

    @classmethod
    def from_der_file(cls, der_file):
        """Read a single DER-encoded certificate from a file.
        Args:
            der_file: the certificate file
        Returns:
            a Certificate object
        Raises:
            ct.crypto.error.ASN1Error: the file does not contain a valid DER
            certificate
            IOError: the file could not be read"""
        with open(der_file, "rb") as f:
            return cls.from_der(f.read())

    def to_der(self):
        """Get the DER-encoding of the certificate."""
        # Currently the cached encoding is never invalidated.
        return self.__cached_der

    def subject_common_name(self):
        """Get the common name of the subject."""
        ret = ""
        rdn_sequence = (self.__asn1_cert.
                        getComponentByName("tbsCertificate").
                        getComponentByName("subject").
                        getComponentByName("rdnSequence"))
        for r in rdn_sequence:
            for attr in r:
                if (attr.getComponentByName("type") ==
                    x509_name.ID_AT_COMMON_NAME):
                    # A certificate should only have one common name.
                    # If it has multiple CNs, we take the last one to be
                    # the most specific.
                    # Use string_value() rather than human readable() to get
                    # just the value without any additional formatting.
                    ret = (attr.getComponentByName("value").getComponent().
                           string_value())
        return ret

    def subject_name(self):
        """Get a human readable string of the subject name attributes."""
        return (self.__asn1_cert.getComponentByName("tbsCertificate").
                getComponentByName("subject").human_readable(wrap=0))

    def issuer_name(self):
        """Get a human readable string of the issuer name attributes."""
        return (self.__asn1_cert.getComponentByName("tbsCertificate").
                getComponentByName("issuer").human_readable(wrap=0))

    def basic_constraint_ca(self):
        """Get the BasicConstraints CA value.
        Returns: True, False, or None.
        """
        try:
            bc = self.__cached_extensions[
                x509_extension.ID_CE_BASIC_CONSTRAINTS]
        except KeyError:
            return None
        return bc[1].getComponentByName("cA")

    def basic_constraint_path_length(self):
        """Get the BasicConstraints pathLenConstraint value.
        Returns: an integral value, or None.
        """
        try:
            bc = self.__cached_extensions[
                x509_extension.ID_CE_BASIC_CONSTRAINTS]
        except KeyError:
            return None
        return bc[1].getComponentByName("pathLenConstraint")

    def not_before(self):
        """Get a time.struct_time representing the notBefore in UTC time.
        Returns: a time.struct_time object."""
        return self.__not_before

    def not_after(self):
        """Get a time.struct_time representing the notAfter in UTC time.
        Returns: a time.struct_time object."""
        return self.__not_after

    def is_temporally_valid_now(self):
        """Determine whether notBefore <= now <= notAfter.
        Returns: True or False."""
        return self.is_temporally_valid_at(time.gmtime())

    def is_expired(self):
        """Returns True if the certificate notAfter is in the past,
        False otherwise."""
        assert self.__not_after is not None
        now = time.gmtime()
        return now > self.__not_after

    def is_not_yet_valid(self):
        """Returns True if the certificate notBefore is in the future,
        False otherwise."""
        assert self.__not_before is not None
        now = time.gmtime()
        return now < self.__not_before

    def is_temporally_valid_at(self, gmtime):
        """Returns True if the certificate was/is/will be valid at the
        given moment, represented as a GMT time struct_time,
        False otherwise."""
        assert self.__not_before is not None
        assert self.__not_after is not None
        return self.__not_before <= gmtime <= self.__not_after

def certs_from_pem(pem_string, skip_invalid_blobs=False):
    """Read multiple PEM-encoded certificates from a string.
    Args:
        pem_string: the certificate string
        skip_invalid_blobs: if False, invalid PEM blobs cause a PemError.
                            If True, invalid blobs are skipped. In
                            non-skip mode, an immediate StopIteration
                            before any valid blocks are found, also
                            causes a PemError exception.
    Yields:
        Certificate objects
    Raises:
        ct.crypto.pem.PemError, ct.crypto.ASN1Error: a block was invalid
        IOError: the file could not be read"""
    for der_cert, _ in pem.pem_blocks(pem_string, Certificate.PEM_MARKERS,
                                      skip_invalid_blobs=skip_invalid_blobs):
        try:
            yield Certificate.from_der(der_cert)
        except error.ASN1Error:
            if not skip_invalid_blobs:
                raise

def certs_from_pem_file(pem_file, skip_invalid_blobs=False):
    """Read multiple PEM-encoded certificates from a file.
    Args:
        pem_file: the certificate file
        skip_invalid_blobs: if False, invalid PEM blobs cause a PemError.
                            If True, invalid blobs are skipped. In
                            non-skip mode, an immediate StopIteration
                            before any valid blocks are found, also
                            causes a PemError exception.
    Yields:
        Certificate objects
    Raises:
        ct.crypto.pem.PemError, ct.crypto.error.ASN1Error:
            a block was invalid
        IOError: the file could not be read"""
    for der_cert, _ in pem.pem_blocks_from_file(
        pem_file, Certificate.PEM_MARKERS,
        skip_invalid_blobs=skip_invalid_blobs):
        try:
            yield Certificate.from_der(der_cert)
        except error.ASN1Error:
            if not skip_invalid_blobs:
                raise
