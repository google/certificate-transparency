import re
from ct.crypto import cert

class CertificateDescription(object):
    """Container for fields in certificate that CertDB is supposed to store."""
    def __init__(self):
        """Returns empty object with all fields set to None"""
        self.der = None
        self.subject_common_names = None

    @classmethod
    def from_cert(cls, certificate):
        """Pulls out interesting fields from certificate, so format of data will
        be similar in every database implementation."""
        der = certificate.to_der()
        try:
            subject_common_names = [sub.value
                                    for sub in
                                    certificate.subject_common_names()]
        except cert.CertificateError:
            subject_common_names = []

        return cls.from_values(der,
                               subject_common_names)

    @staticmethod
    def from_values(der=None, subject_common_names=None):
        """Creates CertificateDescription from provided fields.

        Without this method there is no easy way of creating description for
        unparsable certificate. Values provided are still processed like they
        would be if pulled from certificate."""
        desc = CertificateDescription()
        if der:
            desc.der = der
        if subject_common_names:
            desc.subject_common_names = [u".".join(process_name(
                                            unicode(sub, 'utf-8', 'replace')))
                                         for sub in subject_common_names]
        return desc

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
