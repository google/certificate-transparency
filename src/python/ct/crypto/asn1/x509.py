"""
Copyright (c) 2005-2013, Ilya Etingof <ilya@glas.net>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
-------------------------------------------------------------------------------
This module implements the X509 ASN.1 specification according to the current
(July 2013) RFC 5280: http://www.ietf.org/rfc/rfc5280.txt
It is partially based on the pyasn1 example module for the precursor RFC 2459.
"""

from ct.crypto import error
from ct.crypto.asn1 import oid
from ct.crypto.asn1 import print_util
from ct.crypto.asn1 import types
from ct.crypto.asn1 import x509_name
from ct.crypto.asn1 import x509_time

from pyasn1.type import tag,namedtype,namedval,constraint
from pyasn1 import error as pyasn1_error

# Parts of the ASN.1 specification are implemented separately in x509_name.py
# and (TODO(ekasper)) x509_extensions.py

# In ASN.1, MAX indicates no upper bound, but pyasn1 doesn't have one-sided
# range constraints, so just make it something really big.
_MAX = 1 << 64

class AlgorithmIdentifier(types.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', oid.ObjectIdentifier()),
        # TODO(ekasper): handle the decoding of parameters in a second pass
        namedtype.OptionalNamedType('parameters', types.Any())
        )

# TODO(ekasper): implement standard extensions.
class Extension(types.Sequence):
    PRINT_DELIMITER = ", "
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', oid.ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', types.Boolean('False')),
        namedtype.NamedType('extnValue', types.Any())
        )

class Extensions(types.SequenceOf):
    componentType = Extension()
    sizeSpec = (types.SequenceOf.sizeSpec +
                constraint.ValueSizeConstraint(1, _MAX))

class SubjectPublicKeyInfo(types.Sequence):
     componentType = namedtype.NamedTypes(
         namedtype.NamedType('algorithm', AlgorithmIdentifier()),
         namedtype.NamedType('subjectPublicKey', types.BitString())
         )

class UniqueIdentifier(types.BitString):
    pass

# TODO(ekasper): implement semantic interpretation and pretty-printing of time.
class Time(types.Choice):
    PRINT_LABELS = False
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('utcTime', x509_time.UTCTime()),
        namedtype.NamedType('generalTime', x509_time.GeneralizedTime())
        )

class Validity(types.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('notBefore', Time()),
        namedtype.NamedType('notAfter', Time())
        )

class CertificateSerialNumber(types.Integer):
    # RFC5280 mandates that serial numbers MUST be non-negative and at most 20
    # octets long but also that users SHOULD be prepared to gracefully handle
    # non-conforming certificates. We therefore do not impose any constraints
    # on the serial number.
    def string_value(self):
        try:
            # This will work unless the object is a template with no value.
            return print_util.int_to_hex(int(self))
        except pyasn1_error.PyAsn1Error:
            return "<no value>"

class Version(types.Integer):
    namedValues = namedval.NamedValues(
        ('v1', 0), ('v2', 1), ('v3', 2)
        )

class TBSCertificate(types.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', Version('v1').subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('serialNumber', CertificateSerialNumber()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', x509_name.Name()),
        namedtype.NamedType('validity', Validity()),
        namedtype.NamedType('subject', x509_name.Name()),
        namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType('issuerUniqueID',
                                    UniqueIdentifier().subtype(
                implicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('subjectUniqueID',
                                    UniqueIdentifier().subtype(
                implicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('extensions', Extensions().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)))
        )

class Certificate(types.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertificate', TBSCertificate()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', types.BitString())
        )
