import hashlib
import logging
import re
import time
from ct.crypto import cert
from ct.crypto.asn1 import oid
from ct.crypto.asn1 import x509_extension
from ct.proto import x509_cert_pb2
from ct.proto import x509_extensions_pb2

def from_cert(certificate):
    """Pulls out interesting fields from certificate, so format of data will
    be similar in every database implementation."""
    proto = x509_cert_pb2.X509Certificate()
    proto.der_cert = certificate.to_der()

    try:
        proto.validity.not_before = int(time.mktime(certificate.not_before()))
    except cert.CertificateError:
        pass

    try:
        proto.validity.not_after = int(time.mktime(certificate.not_after()))
    except cert.CertificateError:
        pass

    try:
        proto.public_key_info.algorithm_id = oid_to_string(
                certificate.signature_algorithm()['algorithm'])
    except cert.CertificateError:
        pass
    proto.public_key_info.public_key_text = bit_string_to_hex(
        certificate.subject_public_key())

    try:
        issuer = [(oid_to_string(type_), to_unicode(value.human_readable()))
                   for type_, value in certificate.issuer()]
        for iss in issuer:
            att = proto.issuer.attribute.add()
            att.type, att.value = iss
    except cert.CertificateError:
        pass

    try:
        proto.issuer.common_name.extend(
                [to_unicode('.'.join(process_name(iss.value)))
                 for iss in certificate.issuer_common_name()])
    except cert.CertificateError:
        pass

    try:
        proto.subject.common_name.extend([to_unicode(
                                          ".".join(process_name(sub.value)))
                                 for sub in certificate.subject_common_names()])
    except cert.CertificateError:
        pass

    try:
        for sub in [(oid_to_string(type_), to_unicode(value.human_readable()))
                    for type_, value in certificate.subject()]:
            att = proto.subject.attribute.add()
            att.type, att.value = sub
    except cert.CertificateError:
        pass

    try:
        # alt should be dictionary in format { 'type': value }
        subject_alternative_names = [ (alt.keys()[0],
                                       alt.values()[0].human_readable())
                for alt in certificate.subject_alternative_names()]
    except cert.CertificateError:
        pass

    try:
        proto.version = certificate.version().value - 1
    except cert.CertificateError:
        pass

    try:
        proto.serial_number = str(certificate.serial_number()
                              .human_readable().lower().replace(':',''))
    except cert.CertificateError:
        pass

    try:
        sig = certificate.signature_algorithm()
        proto.signature_algorithm.algorithm_id = oid_to_string(
                sig["algorithm"])
        parameters = sig.get("parameters", None)
        if parameters:
            proto.signature_algorithm.parameter.extend([parameters.value])
    except cert.CertificateError:
        pass

    proto.signature_value = bit_string_to_hex(certificate.signature_value())
    proto.cert_sha256_hash = hashlib.sha256(proto.der_cert).digest()

    ext_dict = {ext['extnID']: ext
                       for ext in certificate.get_extensions()}
    populate_x509_extension(proto.extensions.authority_key_id,
                         ext_dict.get(oid.ID_CE_AUTHORITY_KEY_IDENTIFIER, None))
    populate_x509_extension(proto.extensions.subject_key_id,
                         ext_dict.get(oid.ID_CE_SUBJECT_KEY_IDENTIFIER, None))
    populate_x509_extension(proto.extensions.certificate_policies,
                         ext_dict.get(oid.ID_CE_CERTIFICATE_POLICIES, None))
    populate_x509_extension(proto.extensions.policy_mappings,
                         ext_dict.get(oid.ID_CE_POLICY_MAPPINGS, None))
    populate_x509_extension(proto.extensions.subject_alternative_name,
                         ext_dict.get(oid.ID_CE_SUBJECT_ALT_NAME, None))
    populate_x509_extension(proto.extensions.issuer_alternative_name,
                         ext_dict.get(oid.ID_CE_ISSUER_ALT_NAME, None))
    populate_x509_extension(proto.extensions.name_constraints,
                         ext_dict.get(oid.ID_CE_NAME_CONSTRAINTS, None))
    populate_x509_extension(proto.extensions.policy_constraints,
                         ext_dict.get(oid.ID_CE_POLICY_CONSTRAINTS, None))
    populate_x509_extension(proto.extensions.extended_key_usage,
                         ext_dict.get(oid.ID_CE_EXT_KEY_USAGE, None))
    populate_x509_extension(proto.extensions.inhibit_any_policy,
                         ext_dict.get(oid.ID_CE_INHIBIT_ANY_POLICY, None))
    populate_x509_extension(proto.extensions.authority_key_id,
                         ext_dict.get(oid.ID_CE_AUTHORITY_KEY_IDENTIFIER, None))
    populate_x509_extension(proto.extensions.subject_key_id,
                         ext_dict.get(oid.ID_CE_SUBJECT_KEY_IDENTIFIER, None))
    populate_x509_extension(proto.extensions.certificate_policies,
                         ext_dict.get(oid.ID_CE_CERTIFICATE_POLICIES, None))
    populate_x509_extension(proto.extensions.policy_mappings,
                         ext_dict.get(oid.ID_CE_POLICY_MAPPINGS, None))
    populate_x509_extension(proto.extensions.subject_alternative_name,
                         ext_dict.get(oid.ID_CE_SUBJECT_ALT_NAME, None))
    populate_x509_extension(proto.extensions.issuer_alternative_name,
                         ext_dict.get(oid.ID_CE_ISSUER_ALT_NAME, None))
    populate_x509_extension(proto.extensions.name_constraints,
                         ext_dict.get(oid.ID_CE_NAME_CONSTRAINTS, None))
    populate_x509_extension(proto.extensions.policy_constraints,
                         ext_dict.get(oid.ID_CE_POLICY_CONSTRAINTS, None))
    populate_x509_extension(proto.extensions.extended_key_usage,
                         ext_dict.get(oid.ID_CE_EXT_KEY_USAGE, None))
    populate_x509_extension(proto.extensions.authority_info_access,
                         ext_dict.get(oid.ID_PE_AUTHORITY_INFO_ACCESS, None))

    if ext_dict.get(oid.ID_CE_KEY_USAGE):
        try:
            proto.extensions.key_usage.digital_signature = certificate.key_usage(
                    x509_extension.KeyUsage.DIGITAL_SIGNATURE)
            proto.extensions.key_usage.non_repudiation = certificate.key_usage(
                    x509_extension.KeyUsage.NON_REPUDIATION)
            proto.extensions.key_usage.key_encipherment = certificate.key_usage(
                    x509_extension.KeyUsage.KEY_ENCIPHERMENT)
            proto.extensions.key_usage.data_encipherment = certificate.key_usage(
                    x509_extension.KeyUsage.DATA_ENCIPHERMENT)
            proto.extensions.key_usage.key_agreement = certificate.key_usage(
                    x509_extension.KeyUsage.KEY_AGREEMENT)
            proto.extensions.key_usage.key_cert_sign = certificate.key_usage(
                    x509_extension.KeyUsage.KEY_CERT_SIGN)
            proto.extensions.key_usage.crl_sign = certificate.key_usage(
                    x509_extension.KeyUsage.CRL_SIGN)
            proto.extensions.key_usage.encipher_only = certificate.key_usage(
                    x509_extension.KeyUsage.ENCIPHER_ONLY)
            proto.extensions.key_usage.decipher_only = certificate.key_usage(
                    x509_extension.KeyUsage.DECIPHER_ONLY)
            proto.extensions.key_usage.critical = ext_dict.get(
                    oid.ID_CE_KEY_USAGE)['critical'].value
        except cert.CertificateError:
            pass

    # TODO(laiqu) populate subject directory attribute (requires changing
    # ct.crypto.x509_extension, so it's recognized).
    basic_constraint = ext_dict.get(oid.ID_CE_BASIC_CONSTRAINTS, None)
    if basic_constraint:
        bc_val = basic_constraint['extnValue'].decoded_value
        val = bc_val['cA'].value
        proto.extensions.basic_constraints.ca_flag = val
        path_len = bc_val['pathLenConstraint']
        if path_len:
            proto.extensions.basic_constraints.path_len_constraint = path_len.value
        proto.extensions.basic_constraints.critical = basic_constraint['critical'
                                                                       ].value

    try:
        for crl in certificate.crl_distribution_points():
            crl_pb = proto.extensions.crl_distribution_point.add()
            dis_point = crl['distributionPoint']
            if 'fullName' in dis_point:
                crl_pb.distribution_point.full_name.extend([name.values()[0].value
                        for name in dis_point['fullName']])
            elif 'nameRelativeToCRLIssuer' in dis_point:
                # TODO(laiqu) since RelativeDistinguishedName is SET of pairs,
                # and protobuf only has single bytes issuer_relative_name spot,
                # figure out how to store it (or possibly extend protobuf).
                # There aren't many certificates with this information though.
                logging.INFO("Certificate with nameRelativeToCRLIssuer" +
                             certificate.serial_number().human_readable())
            if crl['reasons']:
                crl_pb.reasons = crl['reasons'].value
            if crl['cRLIssuer']:
                crl_pb.crl_issuer = crl['cRLIssuer'].value
            crl_pb.critical = ext_dict[oid.ID_CE_CRL_DISTRIBUTION_POINTS
                                       ]['critical'].value
    except cert.CertificateError:
        pass
    # TODO(laiqu) figure out how to get freshest_crl
    # TODO(laiqu) pull inhibit_any_policy extension

    specified_extensions = [oid.ID_CE_AUTHORITY_KEY_IDENTIFIER,
                            oid.ID_CE_SUBJECT_KEY_IDENTIFIER,
                            oid.ID_CE_KEY_USAGE,
                            oid.ID_CE_CERTIFICATE_POLICIES,
                            oid.ID_CE_POLICY_MAPPINGS,
                            oid.ID_CE_SUBJECT_ALT_NAME,
                            oid.ID_CE_ISSUER_ALT_NAME,
                            oid.ID_CE_SUBJECT_DIRECTORY_ATTRIBUTES,
                            oid.ID_CE_BASIC_CONSTRAINTS,
                            oid.ID_CE_NAME_CONSTRAINTS,
                            oid.ID_CE_POLICY_CONSTRAINTS,
                            oid.ID_CE_EXT_KEY_USAGE,
                            oid.ID_CE_CRL_DISTRIBUTION_POINTS,
                            oid.ID_CE_INHIBIT_ANY_POLICY,
                            oid.ID_PE_AUTHORITY_INFO_ACCESS,
                            oid.ID_PE_SUBJECT_INFO_ACCESS,]

    other_extensions = []
    for ext in certificate.get_extensions():
        if ext['extnID'] not in specified_extensions:
            pb = x509_extensions_pb2.X509Extension()
            pb.value.extend([ext['extnValue'].value])
            pb.critical = ext['critical'].value
            pb.object_id = oid_to_string(ext['extnID'])
            other_extensions.append(pb)
    proto.extensions.other_extension.extend(other_extensions)
    return proto

def populate_x509_extension(proto, extension):
    if extension is None:
        return
    proto.value.extend([extension['extnValue'].value])
    proto.critical = extension['critical'].value
    proto.object_id = oid_to_string(extension['extnID'])


def to_unicode(str_):
    if type(str_) != unicode:
        return unicode(str_, 'utf-8', 'replace')
    else:
        return str_


def bit_string_to_hex(str_):
    return str_.human_readable_lines(wrap=len(str_.value))[0]

def oid_to_string(oid_):
    return '.'.join([str(val) for val in oid_.value])


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
