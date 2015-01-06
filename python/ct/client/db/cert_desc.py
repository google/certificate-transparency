import re
import hashlib
from ct.crypto import cert
from ct.proto import certificate_pb2

def from_cert(certificate):
    """Pulls out interesting fields from certificate, so format of data will
    be similar in every database implementation."""
    proto = certificate_pb2.X509Description()
    proto.der = certificate.to_der()
    try:
        for sub in [(type_.short_name,
                     to_unicode('.'.join(process_name(value.human_readable()))))
                    for type_, value in certificate.subject()]:
            proto_sub = proto.subject.add()
            proto_sub.type, proto_sub.value = sub
    except cert.CertificateError:
        pass

    try:
        for iss in [(type_.short_name,
                     to_unicode('.'.join(process_name(value.human_readable()))))
                    for type_, value in certificate.issuer()]:
            proto_iss = proto.issuer.add()
            proto_iss.type, proto_iss.value = iss
    except cert.CertificateError:
        pass

    try:
        for alt in certificate.subject_alternative_names():
            proto_alt = proto.subject_alternative_names.add()
            proto_alt.type, proto_alt.value = (alt.component_key(),
                                               to_unicode('.'.join(process_name(
                                      alt.component_value().human_readable()))))
    except cert.CertificateError:
        pass

    try:
        proto.version = str(certificate.version())
    except cert.CertificateError:
        pass

    try:
        proto.serial_number = str(certificate.serial_number().human_readable()
                                  .upper().replace(':', ''))
    except cert.CertificateError:
        pass

    proto.sha256_hash = hashlib.sha256(proto.der).digest()

    return proto


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
