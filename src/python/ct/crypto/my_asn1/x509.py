"""ASN.1 X509 specification."""

from ct.crypto.my_asn1 import oid
from ct.crypto.my_asn1 import types
from ct.crypto.my_asn1 import x509_extension
from ct.crypto.my_asn1 import x509_name


class Version(types.Integer):
    pass


class CertificateSerialNumber(types.Integer):
    pass


class AlgorithmIdentifier(types.Sequence):
    components = (
        (types.Component("algorithm", oid.ObjectIdentifier)),
        (types.Component("parameters", types.Any, optional=True))
        )


class Time(types.Choice):
    components = {"utcTime": types.UTCTime,
                  "generalTime": types.GeneralizedTime}


class Validity(types.Sequence):
    components = (
        (types.Component("notBefore", Time)),
        (types.Component("notAfter", Time))
        )


class UniqueIdentifier(types.BitString):
    pass


class SubjectPublicKeyInfo(types.Sequence):
    components = (
        (types.Component("algorithm", AlgorithmIdentifier)),
        (types.Component("subjectPublicKey", types.BitString))
        )


class TBSCertificate(types.Sequence):
    components = (
        (types.Component("version", Version.explicit(0))),
        (types.Component("serialNumber", CertificateSerialNumber)),
        (types.Component("signature", AlgorithmIdentifier)),
        (types.Component("issuer", x509_name.Name)),
        (types.Component("validity", Validity)),
        (types.Component("subject", x509_name.Name)),
        (types.Component("subjectPublicKeyInfo", SubjectPublicKeyInfo)),
        (types.Component("issuerUniqueID", UniqueIdentifier.implicit(1),
                         optional=True)),
        (types.Component("subjectUniqueID", UniqueIdentifier.implicit(2),
                         optional=True)),
        (types.Component("extensions",
                         x509_extension.Extensions.explicit(3), optional=True))
        )


class Certificate(types.Sequence):
    components = (
        (types.Component("tbsCertificate", TBSCertificate)),
        (types.Component("signatureAlgorithm", types.Any)),
        (types.Component("signatureValue", types.BitString))
        )
