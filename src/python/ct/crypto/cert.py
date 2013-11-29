
"""X509 Certificate API."""

import collections
import hashlib
import time

from ct.crypto import error
from ct.crypto import name
from ct.crypto import pem
from ct.crypto.asn1 import oid
from ct.crypto.asn1 import x509


class CertificateError(error.Error):
    """Certificate has errors."""
    pass


class Certificate(object):
    """X509 certificates."""
    PEM_MARKERS = ("CERTIFICATE",)

    def __init__(self, der_string, strict_der=True):
        """Initialize from a DER string.

        Args:
            der_string: a binary string containing the DER-encoded
                certificate.
            strict_der: if False, tolerate some non-fatal DER errors.

        Raises:
            error.ASN1Error: invalid encoding.
        """
        # ASN.1 errors fall through.
        self._asn1_cert = x509.Certificate.decode(der_string,
                                                  strict=strict_der)
        # The general philosophy here is that a certificate decoded in
        # strict mode should never raise CertificateErrors later on in the
        # code. Strict mode already catches corrupt extensions, to the extent
        # that their IDs are recognized; in addition, we have to ensure that
        # no extension appears more than once.
        # TODO(ekasper): move this check to the Extensions class.
        if strict_der and self._has_multiple_extension_values():
            raise error.ASN1Error("Multiple extensions")
        # Certs are primarily used as read-only objects so we cache the DER
        # encoding. If any public setters or other methods modifying the
        # contents of the certificate are ever added to this class, they must
        # invalidate the cached encoding.
        # TODO(ekasper): get rid of the cached string: I think we should
        # (a) offer read-only API calls for common usage; but
        # (b) be pythonic and allow raw access to the underlying mutable ASN.1
        # structure for applications that need to inspect it in detail.
        # Encoding is so fast that we hardly care about performance gain;
        # we just need to ensure that non-strict certs keep their original
        # encoding.
        self._cached_der = der_string

    def __repr__(self):
        # This prints the full ASN1 representation. Useful for debugging.
        return repr(self._asn1_cert)

    def __str__(self):
        return self._asn1_cert.human_readable(label=self.__class__.__name__)

    @classmethod
    def from_pem(cls, pem_string, strict_der=True):
        """Read a single PEM-encoded certificate from a string.

        Args:
            pem_string: the certificate string.
            strict_der: if False, tolerate some non-fatal DER errors.

        Returns:
            a Certificate object.

        Raises:
            ct.crypto.pem.PemError, ct.crypto.error.ASN1Error: the string
            does not contain a valid PEM certificate.
        """
        der_cert, _ = pem.from_pem(pem_string, cls.PEM_MARKERS)
        return cls.from_der(der_cert, strict_der=strict_der)

    def _has_multiple_extension_values(self):
        extns = self._asn1_cert["tbsCertificate"]["extensions"] or []
        extn_value_count = collections.Counter([e["extnID"] for e in extns])
        return any([c > 1 for c in extn_value_count.values()])

    # TODO(ekasper): add a test for the CertificateError case.
    def _get_decoded_extension_value(self, extn_id):
        """Get the decoded value of an extension."""
        extns = self._asn1_cert["tbsCertificate"]["extensions"] or []
        extn_values = [e["extnValue"] for e in extns if e["extnID"] == extn_id]
        if not extn_values:
            return None
        if len(extn_values) > 1:
            # TODO(ekasper): could refine this to only raise when the multiple
            # extension values are conflicting.
            raise CertificateError("Multiple extension values")
        if extn_values[0].decoded_value is None:
            raise CertificateError("Corrupt or unrecognized extension: %s"
                                   % extn_values[0].value)
        return extn_values[0].decoded_value

    @classmethod
    def from_der(cls, der_string, strict_der=True):
        """Read a single DER-encoded certificate from a string.

        This is just an alias to __init__ to match from_pem().

        Args:
            der_string: the certificate string.
            strict_der: if False, tolerate some non-fatal DER errors.

        Returns:
            a Certificate object.

        Raises:
            ct.crypto.error.ASN1Error: the string does not contain a valid
            DER certificate.
        """
        return cls(der_string, strict_der=strict_der)

    @classmethod
    def from_pem_file(cls, pem_file, strict_der=True):
        """Read a single PEM-encoded certificate from a file.

        Args:
            pem_file: the certificate file.
            strict_der: if False, tolerate some non-fatal DER errors.

        Returns:
            a Certificate object
        Raises:
            ct.crypto.pem.PemError, ct.crypto.error.ASN1Error: the file does not
            contain a valid PEM certificate
            IOError: the file could not be read,
        """
        der_cert, _ = pem.from_pem_file(pem_file, cls.PEM_MARKERS)
        return cls.from_der(der_cert, strict_der=strict_der)

    @classmethod
    def from_der_file(cls, der_file, strict_der=True):
        """Read a single DER-encoded certificate from a file.

        Args:
            der_file: the certificate file.
            strict_der: if False, tolerate some non-fatal DER errors.

        Returns:
            a Certificate object.

        Raises:
            ct.crypto.error.ASN1Error: the file does not contain a valid DER
            certificate
            IOError: the file could not be read.
        """
        with open(der_file, "rb") as f:
            return cls.from_der(f.read(), strict_der=strict_der)

    def to_der(self):
        """Get the DER-encoding of the certificate."""
        # Currently the cached encoding is never invalidated.
        return self._cached_der

    def version(self):
        """Get the version.

        Returns:
            an integral value of the version (i.e., V1 is 0).
        """
        return int(self._asn1_cert["tbsCertificate"]["version"])

    # TODO(ekasper): redo the Name API.
    # https://code.google.com/p/certificate-transparency/issues/detail?id=13
    def subject_common_name(self):
        """Get the common name of the subject."""
        ret = ""
        rdn_sequence = self._asn1_cert["tbsCertificate"]["subject"]
        for r in rdn_sequence:
            for attr in r:
                if attr["type"] == oid.ID_AT_COMMON_NAME:
                    # A certificate should only have one common name.
                    # If it has multiple CNs, we take the last one to be
                    # the most specific.
                    if not attr["value"].decoded:
                        raise CertificateError("Corrupt name attribute")
                    ret = attr["value"].decoded_value.component_value().value
        return ret

    def subject_name(self):
        """Get a human readable string of the subject name attributes."""
        return (self._asn1_cert["tbsCertificate"]["subject"].
                human_readable(wrap=0))

    def issuer_name(self):
        """Get a human readable string of the issuer name attributes."""
        return (self._asn1_cert["tbsCertificate"]["issuer"].
                human_readable(wrap=0))

    def serial_number(self):
        """Get the serial number.

        While the serial number is an integer, it could be very large.
        RFC 5280 specification states is should not be longer than 20 octets,
        and also states users SHOULD be prepared to gracefully
        handle non-conforming certificates.

        Returns:
           integer

        """
        return int(self._asn1_cert["tbsCertificate"]["serialNumber"])

    def basic_constraint_ca(self):
        """Get the BasicConstraints CA value.

        Returns:
            True, False, or None.

        Raises:
            CertificateError: corrupt extension, or multiple extensions.
        """
        # CertificateErrors fall through.
        bc = self._get_decoded_extension_value(oid.ID_CE_BASIC_CONSTRAINTS)
        if bc is None:
            return None

        return None if bc["cA"] is None else bool(bc["cA"])

    def subject_alternative_names(self):
        """Get the Alternative Names extension.

        Returns:
            Array of alternative names (name.GeneralName)

        Raises:
            CertificateError: corrupt extension, or multiple extensions.
        """
        # CertificateErrors fall through.
        general_names = self._get_decoded_extension_value(
            oid.ID_CE_SUBJECT_ALT_NAME)
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
        bc = self._get_decoded_extension_value(oid.ID_CE_BASIC_CONSTRAINTS)
        if bc is None:
            return None

        pathlen = bc["pathLenConstraint"]
        return None if pathlen is None else int(pathlen)

    def not_before(self):
        """Get a time.struct_time representing the notBefore in UTC time.

        Returns:
            a time.struct_time object.

        Raises:
            CertificateError: corrupt notBefore value.
        """
        return (self._asn1_cert["tbsCertificate"]["validity"]["notBefore"].
                component_value().gmtime())

    def not_after(self):
        """Get a time.struct_time representing the notAfter in UTC time.

        Returns:
            a time.struct_time object.

        Raises:
            CertificateError: corrupt notAfter value.
        """
        return (self._asn1_cert["tbsCertificate"]["validity"]["notAfter"].
                component_value().gmtime())

    def is_temporally_valid_now(self):
        """Determine whether notBefore <= now <= notAfter.

        Returns:
            True or False.

        Raises:
            CertificateError: corrupt time.
        """
        return self.is_temporally_valid_at(time.gmtime())

    def is_expired(self):
        """Is certificate notAfter in the past?

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

    def fingerprint(self, hashfunc="sha1"):
        """Get the certificate fingerprint.

        Args:
            hashfunc: name of a hash function. Algorithms always present are
                'md5', 'sha1', 'sha224', 'sha256', 'sha384', and 'sha512'.
        Returns:
            a (binary) hash digest of the DER encoding.
        """
        h = hashlib.new(hashfunc)
        h.update(self._cached_der)
        return h.digest()


def certs_from_pem(pem_string, skip_invalid_blobs=False, strict_der=True):
    """Read multiple PEM-encoded certificates from a string.

    Args:
        pem_string: the certificate string
        skip_invalid_blobs: if False, invalid PEM blobs cause a PemError.
            If True, invalid blobs are skipped. In non-skip mode, an
            immediate StopIteration before any valid blocks are found also
            causes a PemError exception.
        strict_der: if False, tolerate some non-fatal DER errors.

    Yields:
        Certificate objects.

    Raises:
        ct.crypto.pem.PemError, ct.crypto.ASN1Error: a block was invalid
        IOError: the file could not be read.
    """
    for der_cert, _ in pem.pem_blocks(pem_string, Certificate.PEM_MARKERS,
                                      skip_invalid_blobs=skip_invalid_blobs):
        try:
            yield Certificate.from_der(der_cert, strict_der=strict_der)
        except error.ASN1Error:
            if not skip_invalid_blobs:
                raise


def certs_from_pem_file(pem_file, skip_invalid_blobs=False, strict_der=True):
    """Read multiple PEM-encoded certificates from a file.

    Args:
        pem_file: the certificate file.
        skip_invalid_blobs: if False, invalid PEM blobs cause a PemError.
            If True, invalid blobs are skipped. In non-skip mode, an
            immediate StopIteration before any valid blocks are found also
            causes a PemError exception.
        strict_der: if False, tolerate some non-fatal DER errors.

    Yields:
        Certificate objects.

    Raises:
        ct.crypto.pem.PemError, ct.crypto.error.ASN1Error:
            a block was invalid
        IOError: the file could not be read.
    """
    for der_cert, _ in pem.pem_blocks_from_file(
        pem_file, Certificate.PEM_MARKERS,
        skip_invalid_blobs=skip_invalid_blobs):
        try:
            yield Certificate.from_der(der_cert, strict_der=strict_der)
        except error.ASN1Error:
            if not skip_invalid_blobs:
                raise
