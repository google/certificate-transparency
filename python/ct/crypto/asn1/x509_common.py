"""ASN.1 X509 base components."""

from ct.crypto.asn1 import oid
from ct.crypto.asn1 import print_util
from ct.crypto.asn1 import types


class Version(types.Integer):
    pass


class CertificateSerialNumber(types.Integer):
    def __str__(self):
        return print_util.int_to_hex(int(self))


class AlgorithmIdentifier(types.Sequence):
    components = (
        (types.Component("algorithm", oid.ObjectIdentifier)),
        (types.Component("parameters", types.Any, optional=True))
        )


class UniqueIdentifier(types.BitString):
    pass


class SubjectPublicKeyInfo(types.Sequence):
    components = (
        (types.Component("algorithm", AlgorithmIdentifier)),
        (types.Component("subjectPublicKey", types.BitString))
        )
