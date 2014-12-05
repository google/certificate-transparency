from ct.crypto import cert
import re
from ct.cert_analysis.observation import Observation

class DNSNamesObservation(Observation):
    def __init__(self, description, *args, **kwargs):
        super(DNSNamesObservation, self).__init__("dNSNames: " + description,
                                                  *args, **kwargs)


class InvalidCharacter(DNSNamesObservation):
    def __init__(self, *args, **kwargs):
        super(InvalidCharacter, self).__init__("invalid character in name",
                                               *args, **kwargs)


class CorruptSANExtension(DNSNamesObservation):
    def __init__(self):
        super(CorruptSANExtension, self).__init__("corrupt extension")


class CheckValidityOfDnsnames(object):
    # if this regex matches in any way, it can't be dnsname
    NOT_DNSNAME_REGEX = re.compile('[^a-zA-Z0-9\-.*]')

    @staticmethod
    def check(certificate):
        """Checks whether dNSNames contains correct characters.

        Returns:
            array containing InvalidCharacter or empty array
        """
        observations = []
        try:
            for name in certificate.subject_dns_names():
                # if there are funny characters from other encodings they will
                # cause either unicode to fail, or they will stay in idna
                # encoding and caught by regex
                try:
                    utf_name = unicode(name.value, 'utf-8')
                except UnicodeError:
                    observations.append(
                        InvalidCharacter('failed to encode in utf-8',
                                         name.value))
                    continue
                try:
                    idna_name = utf_name.encode('idna')
                    for match in CheckValidityOfDnsnames.NOT_DNSNAME_REGEX.findall(
                            idna_name):
                        reason = None
                        if match == '@':
                            reason = 'suspected email address'
                        obs = InvalidCharacter(reason,
                                               (name.value, idna_name, match))
                        observations += [obs]
                except UnicodeError:
                    observations.append(
                        InvalidCharacter('failed to encode in idna',
                                         utf_name))
        except cert.CertificateError:
            pass
        return observations

class CheckCorruptSANExtension(object):
    """Checks whether SAN extension is corrupt.

    Returns:
        array containing CorruptSANExtension or None
    """
    @staticmethod
    def check(certificate):
        try:
            certificate.subject_dns_names()
        except cert.CertificateError:
            return [CorruptSANExtension()]
