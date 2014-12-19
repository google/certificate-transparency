import re
from ct.crypto import cert
from ct.proto import certificate_pb2

class CertificateDescription(object):
    """Container for fields in certificate that CertDB is supposed to store."""
    def __init__(self):
        self.der = None
        self.proto = certificate_pb2.X509Description()

    @classmethod
    def from_cert(cls, certificate):
        """Pulls out interesting fields from certificate, so format of data will
        be similar in every database implementation."""
        der = certificate.to_der()
        try:
            subject_names = [sub.value for sub in
                                    certificate.subject_common_names()]
        except cert.CertificateError:
            subject_names = []

        try:
            alt_subject_names = [sub.value
                                 for sub in
                                 certificate.subject_dns_names()]
        except cert.CertificateError:
            alt_subject_names = []

        try:
            version = str(certificate.version().human_readable())
        except cert.CertificateError:
            version = None

        try:
            serial_number = str(certificate.serial_number().value)
        except cert.CertificateError:
            serial_number = None

        try:
            ip_addresses = [str(ip) for ip in certificate.subject_ip_addresses()]
        except cert.CertificateError:
            ip_addresses = []

        return cls.from_values(der,
                               subject_names,
                               alt_subject_names,
                               version,
                               serial_number,
                               ip_addresses)

    @staticmethod
    def from_values(der=None, subject_names=None, alt_subject_names=None,
                    version=None, serial_number=None, ip_addresses=None):
        """Creates CertificateDescription from provided fields.

        Without this method there is no easy way of creating description for
        unparsable certificate. Values provided are still processed like they
        would be if pulled from certificate."""
        desc = CertificateDescription()
        if der:
            desc.der = der
        if subject_names:
            desc.proto.subject_names.extend([to_unicode(
                                             ".".join(process_name(sub)))
                                            for sub in subject_names])
        if alt_subject_names:
            desc.proto.alt_subject_names.extend([to_unicode(
                                                 ".".join(process_name(alt)))
                                                 for alt in alt_subject_names])
        if version:
            desc.proto.version = to_unicode(version)
        if serial_number:
            desc.proto.serial_number = to_unicode(serial_number)
        if ip_addresses:
            desc.proto.ip_addresses.extend([to_unicode(ip)
                                            for ip in ip_addresses])
        return desc

    def __getitem__(self, name):
        if name in [field[0].name for field in self.proto.ListFields()]:
            return getattr(self.proto, name)


def to_unicode(str_):
    return unicode(str_, 'utf-8', 'replace')

def process_name(subject, reverse=True):
    # RFCs for DNS names: RFC 1034 (sect. 3.5), RFC 1123 (sect. 2.1);
    # for common names: RFC 5280.
    # However we probably do not care about full RFC compliance here
    # (e.g. we ignore that a compliant label cannot begin with a hyphen,
    # we accept multi-wildcard names, etc.).
    #
    # For now, make indexing work for the common case:
    # allow letter-digit-hyphen, as well as wildcards (RFC 2818).
    forbidden = re.compile(r"[^a-z\d\-\*]")
    subject = subject.lower()
    labels = subject.split(".")
    valid = all(map(lambda x: len(x) and not forbidden.search(x), labels))

    if valid:
        # ["com", "example", "*"], ["com", "example", "mail"],
        # ["localhost"], etc.
        return list(reversed(labels)) if reverse else labels

    else:
        # ["john smith"], ["trustworthy certificate authority"],
        # ["google.com\x00"], etc.
        # TODO(ekasper): figure out what to do (use stringprep as specified
        # by RFC 5280?) to properly handle non-letter-digit-hyphen names.
        return [subject]
