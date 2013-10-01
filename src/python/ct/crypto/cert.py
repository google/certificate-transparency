import logging
import time
from collections import defaultdict
from collections import namedtuple

from ct.crypto import error
from ct.crypto import name
from ct.crypto import pem
from ct.crypto.asn1 import oid
from ct.crypto.asn1 import x509
from ct.crypto.asn1 import x509_extension
from ct.crypto.asn1 import x509_name

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1 import error as pyasn1_error


class CertificateError(error.Error):
    """Certificate has errors."""
    pass


class Certificate(object):
    PEM_MARKERS = ("CERTIFICATE",)
    _ASN1_SPEC = x509.Certificate()

    # Critical: the critical bit. Always present.
    # decoded_value: decoded value. May be None if decoding failed.
    # raw_value: raw_value. Always present. (Currently not used but will be
    # used for debugging and inspection of malformed certificates.)
    # error: decoding error, or None.
    CachedExtension = namedtuple("CachedExtension",
                                 ["critical", "decoded_value", "raw_value",
                                  "decoding_error"])

    class CachedTime(object):
        def __init__(self, raw_value):
            # time: decoded time struct.
            # raw_value: raw (string) time value. Always present.
            # error: decoding error, or None.
            self.__raw_value = raw_value
            self.__decoded_time = None
            self.__decoding_error = None
            try:
                self.__decoded_time = raw_value.gmtime()
            except error.ASN1Error as e:
                # We can't raise here because we don't want to abort __init__,
                # so we cache the exception and raise when asked for the decoded
                # time
               self.__decoding_error = e

        @property
        def decoded_time(self):
            if self.__decoded_time is None:
                raise CertificateError("Corrupt time: %s" %
                                       self.__decoding_error)
            return self.__decoded_time


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

        self.__not_before = None
        self.__not_after = None
        self.__cache_expiry()
        # id -> [CachedExtension]
        self.__cached_extensions = defaultdict(list)
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
        self.__not_before = self.CachedTime(
            self.__asn1_cert.getComponentByName("tbsCertificate").
            getComponentByName("validity").
            getComponentByName("notBefore").getComponent())

        self.__not_after = self.CachedTime(
            self.__asn1_cert.getComponentByName("tbsCertificate").
            getComponentByName("validity").
            getComponentByName("notAfter").getComponent())

    def __cache_extensions(self):
        extensions = (self.__asn1_cert.getComponentByName("tbsCertificate").
                      getComponentByName("extensions"))
        if not extensions:
            return
        for ext in extensions:
            decoding_error = None
            decoded_value = None
            raw_value = ext.getComponentByName("extnValue")
            try:
                decoded_value = ext.get_decoded_value()
            except error.ASN1Error as e:
                # Either a corrupt extension, or one with an unknown type.
                decoding_error = e

            extn_id = ext.getComponentByName("extnID")
            self.__cached_extensions[extn_id].append(self.CachedExtension(
                ext.getComponentByName("critical"), decoded_value, raw_value,
                decoding_error))

    # TODO(ekasper): add a test for the CertificateError case.
    def __get_decoded_extension_value(self, extn_id):
        extn_values = self.__cached_extensions[extn_id]
        if not extn_values:
            return None
        if len(extn_values) > 1:
            # TODO(ekasper): could refine this to only raise when the multiple
            # extension values are conflicting.
            raise CertificateError("Multiple extensions")
        if extn_values[0].decoded_value is None:
            raise CertificateError("Corrupt or unrecognized extension: %s"
                                   % extn_values[0].decoding_error)
        return extn_values[0].decoded_value

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

    def version(self):
        """Get the version.
        Returns:
            an integral value of the version (i.e., V1 is 0).
        """
        return int(self.__asn1_cert.getComponentByName("tbsCertificate").
                   getComponentByName("version"))

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

    def serial_number(self):
        """Get the serial number.

        While the serial number is an integer, it could be very large.
        RFC 5280 specification states is should not be longer than 20 octets,
        and also states users SHOULD be prepared to gracefully
        handle non-conforming certificates.

        Returns:
           integer

        """
        return int(self.__asn1_cert.getComponentByName("tbsCertificate").
                   getComponentByName("serialNumber"))

    def basic_constraint_ca(self):
        """Get the BasicConstraints CA value.

        Returns:
            True, False, or None.

        Raises:
            CertificateError: corrupt extension, or multiple extensions.
        """
        # CertificateErrors fall through.
        bc = self.__get_decoded_extension_value(
            x509_extension.ID_CE_BASIC_CONSTRAINTS)
        if bc is None:
            return None

        bc_ca = bc.getComponentByName("cA")
        return None if bc_ca is None else bool(bc_ca)

    def subject_alternative_names(self):
        """Get the Alternative Names extension.

        Returns:
            Array of alternative names (name.GeneralName)

        Raises:
            CertificateError: corrupt extension, or multiple extensions.
        """
        # CertificateErrors fall through.
        general_names = self.__get_decoded_extension_value(
            x509_extension.ID_CE_SUBJECT_ALT_NAME)
        if general_names is None:
            return []
        return name.parse_alternative_names(general_names)

    def basic_constraint_path_length(self):
        """Get the BasicConstraints pathLenConstraint value.

        Returns:
            an integral value, or None.

        Raises:
            CertificateError: corrupt extension, or multiple extensions.
        """
        bc = self.__get_decoded_extension_value(
            x509_extension.ID_CE_BASIC_CONSTRAINTS)
        if bc is None:
            return None

        pathlen = bc.getComponentByName("pathLenConstraint")
        return None if pathlen is None else int(pathlen)

    def not_before(self):
        """Get a time.struct_time representing the notBefore in UTC time.

        Returns:
            a time.struct_time object.

        Raises:
            CertificateError: corrupt notBefore value.
        """
        return self.__not_before.decoded_time

    def not_after(self):
        """Get a time.struct_time representing the notAfter in UTC time.

        Returns:
            a time.struct_time object.

        Raises:
            CertificateError: corrupt notAfter value.
        """
        return self.__not_after.decoded_time

    def is_temporally_valid_now(self):
        """Determine whether notBefore <= now <= notAfter.

        Returns:
            True or False.

        Raises:
            CertificateError: corrupt time.
        """
        return self.is_temporally_valid_at(time.gmtime())

    def is_expired(self):
        """ Is certificate notAfter in the past?

        Returns:
            True or False.

        Raises:
            CertificateError: corrupt time.
        """
        now = time.gmtime()
        return now > self.not_after()

    def is_not_yet_valid(self):
        """Is certificate notBefore in the future?

        Returns:
            True or False.

        Raises:
            CertificateError: corrupt time.
        """
        now = time.gmtime()
        return now < self.not_before()

    def is_temporally_valid_at(self, gmtime):
        """Is certificate valid at the given moment?

        Args:
            gmtime: a struct_time GMT time.

        Returns:
            True or False.

        Raises:
            CertificateError: corrupt time.
        """
        return self.not_before() <= gmtime <= self.not_after()

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
