"""Verify CT log statements."""

import hashlib
import io
import struct

from ct.crypto import error
from ct.crypto import merkle
from ct.crypto import pem
from ct.crypto.asn1 import oid
from ct.crypto.asn1 import x509_extension as x509_ext
from ct.crypto.asn1 import x509_name
from ct.proto import client_pb2
from ct.proto import ct_pb2
from ct.serialization import tls_message
import ecdsa

def decode_signature(signature):
    """Decode the TLS-encoded serialized signature.

    Args:
        signature: TLS-encoded signature.

    Returns:
        a tuple of (hash algorithm, signature algorithm, signature data)

    Raises:
        ct.crypto.error.EncodingError: invalid TLS encoding.
    """

    sig_stream = io.BytesIO(signature)

    sig_prefix = sig_stream.read(2)
    if len(sig_prefix) != 2:
        raise error.EncodingError("Invalid algorithm prefix %s" %
                                      sig_prefix.encode("hex"))
    hash_algo, sig_algo = struct.unpack(">BB", sig_prefix)
    if (hash_algo != ct_pb2.DigitallySigned.SHA256 or
        sig_algo != ct_pb2.DigitallySigned.ECDSA):
        raise error.EncodingError("Invalid algorithm(s) %d, %d" %
                                  (hash_algo, sig_algo))

    length_prefix = sig_stream.read(2)
    if len(length_prefix) != 2:
        raise error.EncodingError("Invalid signature length prefix %s" %
                                  length_prefix.encode("hex"))
    sig_length, = struct.unpack(">H", length_prefix)
    remaining = sig_stream.read()
    if len(remaining) != sig_length:
        raise error.EncodingError("Invalid signature length %d for "
                                  "signature %s with length %d" %
                                  (sig_length, remaining.encode("hex"),
                                   len(remaining)))
    return (hash_algo, sig_algo, remaining)

def _get_precertificate_issuer(chain):
    try:
        issuer = chain[1]
    except IndexError:
        raise error.IncompleteChainError(
                "Chain with PreCertificate must contain issuer.")

    if not issuer.extended_key_usage(oid.CT_PRECERTIFICATE_SIGNING):
        return issuer
    else:
        try:
            return chain[2]
        except IndexError:
            raise error.IncompleteChainError(
                "Chain with PreCertificate signed by PreCertificate "
                "Signing Cert must contain issuer.")

def _find_extension(asn1, extn_id):
    """Find an extension from a certificate's ASN.1 representation

    Args:
        asn1: x509.Certificate instance.
        extn_id: OID of the extension to look for.

    Returns:
        The decoded value of the extension, or None if not found.
        This is a reference and can be modified.
    """
    for e in asn1["tbsCertificate"]["extensions"]:
        if e["extnID"] == extn_id:
            return e["extnValue"].decoded_value

    return None

def _remove_extension(asn1, extn_id):
    """Remove an extension from a certificate's ASN.1 representation

    Args:
        asn1: x509.Certificate instance.
        extn_id: OID of the extension to be removed.
    """
    asn1["tbsCertificate"]["extensions"] = (
        filter(lambda e: e["extnID"] != extn_id,
               asn1["tbsCertificate"]["extensions"])
    )

def _encode_tbs_certificate_for_validation(cert, issuer):
    """Normalize a Certificate for CT Signing / Verification
    The poison and embedded sct extensions are removed if present,
    and the issuer information is changed to match the one given in
    argument. The resulting TBS certificate is encoded.

    Args:
        cert: Certificate instance to be normalized
        issuer: Issuer certificate used to fix issuer information in TBS
                certificate.

    Returns:
        DER encoding of the normalized TBS Certificate
    """
    asn1 = cert.to_asn1()
    issuer_asn1 = issuer.to_asn1()

    _remove_extension(asn1, oid.CT_POISON)
    _remove_extension(asn1, oid.CT_EMBEDDED_SCT_LIST)
    asn1["tbsCertificate"]["issuer"] = issuer_asn1["tbsCertificate"]["subject"]

    akid = _find_extension(asn1, oid.ID_CE_AUTHORITY_KEY_IDENTIFIER)
    if akid is not None:
        akid[x509_ext.KEY_IDENTIFIER] = issuer.subject_key_identifier()
        akid[x509_ext.AUTHORITY_CERT_SERIAL_NUMBER] = issuer.serial_number()
        akid[x509_ext.AUTHORITY_CERT_ISSUER] = [
            x509_name.GeneralName({
                x509_name.DIRECTORY_NAME: issuer_asn1["tbsCertificate"]["issuer"]
            })
        ]

    return asn1["tbsCertificate"].encode()

def _is_precertificate(cert):
    return (cert.has_extension(oid.CT_POISON) or
            cert.has_extension(oid.CT_EMBEDDED_SCT_LIST))

def _create_dst_entry(sct, chain):
    """Create a Digitally Signed Timestamped Entry to be validated

    Args:
        sct: client_pb2.SignedCertificateTimestamp instance.
        chain: list of Certificate instances.

    Returns:
        client_pb2.DigitallySignedTimestampedEntry instance with all
        fields set.

    Raises:
        ct.crypto.error.IncompleteChainError: a certificate is missing
            from the chain.
    """

    try:
        leaf_cert = chain[0]
    except IndexError:
        raise error.IncompleteChainError(
                "Chain must contain leaf certificate.")

    entry = client_pb2.DigitallySignedTimestampedEntry()
    entry.sct_version = ct_pb2.V1
    entry.signature_type = client_pb2.CERTIFICATE_TIMESTAMP
    entry.timestamp = sct.timestamp
    entry.ct_extensions = sct.extensions

    if _is_precertificate(leaf_cert):
        issuer = _get_precertificate_issuer(chain)

        entry.entry_type = client_pb2.PRECERT_ENTRY
        entry.pre_cert.issuer_key_hash = issuer.key_hash('sha256')
        entry.pre_cert.tbs_certificate = (
            _encode_tbs_certificate_for_validation(leaf_cert, issuer)
        )
    else:
        entry.entry_type = client_pb2.X509_ENTRY
        entry.asn1_cert = leaf_cert.to_der()

    return entry

class LogVerifier(object):
    """CT log verifier."""
    __ECDSA_READ_MARKERS = ("PUBLIC KEY", "ECDSA PUBLIC KEY")
    __ECDSA_WRITE_MARKER = "ECDSA PUBLIC KEY"

    def __init__(self, key_info, merkle_verifier=merkle.MerkleVerifier()):
        """Initialize from KeyInfo protocol buffer and a MerkleVerifier."""
        self.__merkle_verifier = merkle_verifier
        if key_info.type != client_pb2.KeyInfo.ECDSA:
            raise error.UnsupportedAlgorithmError("Key type %d not supported" %
                                                  key_info.type)

        # Will raise a PemError on invalid encoding
        self.__der, _ = pem.from_pem(key_info.pem_key,
                                     LogVerifier.__ECDSA_READ_MARKERS)
        try:
            self.__pubkey = ecdsa.VerifyingKey.from_der(self.__der)
        except ecdsa.der.UnexpectedDER as e:
            raise error.EncodingError(e)

    def __repr__(self):
        return "%r(public key: %r)" % (self.__class__.__name__,
                                       pem.to_pem(self.__der,
                                                  self.__ECDSA_WRITE_MARKER))

    def __str__(self):
        return "%s(public key: %s)" % (self.__class__.__name__,
                                       pem.to_pem(self.__der,
                                                  self.__ECDSA_WRITE_MARKER))

    def _encode_sth_input(self, sth_response):
        if len(sth_response.sha256_root_hash) != 32:
            raise error.EncodingError("Wrong hash length: expected 32, got %d" %
                                      len(sth_response.sha256_root_hash))
        return struct.pack(">BBQQ32s", ct_pb2.V1, ct_pb2.TREE_HEAD,
                           sth_response.timestamp, sth_response.tree_size,
                           sth_response.sha256_root_hash)

    def _verify(self, signature_input, signature):
        try:
            return self.__pubkey.verify(signature, signature_input,
                                        hashfunc=hashlib.sha256,
                                        sigdecode=ecdsa.util.sigdecode_der)
        except ecdsa.der.UnexpectedDER:
            raise error.EncodingError("Invalid DER encoding for signature %s",
                                      signature.encode("hex"))
        except ecdsa.keys.BadSignatureError:
            raise error.SignatureError("Signature did not verify: %s",
                                       signature.encode("hex"))

    @error.returns_true_or_raises
    def verify_sth(self, sth_response):
        """Verify the STH Response.

        Args:
            sth_response: client_pb2.SthResponse proto. The response must have
                all fields present.

        Returns:
            True. The return value is enforced by a decorator and need not be
                checked by the caller.

        Raises:
            ct.crypto.error.EncodingError: failed to encode signature input,
                or decode the signature.
            ct.crypto.error.SignatureError: invalid signature.
        """
        signature_input = self._encode_sth_input(sth_response)
        #TODO(eranm): Pass the actual hash and signature algorithms to the
        # verify method.
        (_, _, signature) = decode_signature(sth_response.tree_head_signature)
        return self._verify(signature_input, signature)

    @staticmethod
    @error.returns_true_or_raises
    def verify_sth_temporal_consistency(old_sth, new_sth):
        """Verify the temporal consistency for two STH responses.

        For two STHs, verify that the newer STH has bigger tree size.
        Does not verify STH signatures or consistency of hashes.

        Args:
            old_sth: client_pb2.SthResponse proto. The STH with the older
                timestamp must be supplied first.
            new_sth: client_pb2.SthResponse proto.

        Returns:
            True. The return value is enforced by a decorator and need not be
                checked by the caller.

        Raises:
            ct.crypto.error.ConsistencyError: STHs are inconsistent
            ValueError: "Older" STH is not older.
        """
        if old_sth.timestamp > new_sth.timestamp:
            raise ValueError("Older STH has newer timestamp (%d vs %d), did "
                             "you supply inputs in the wrong order?" %
                             (old_sth.timestamp, new_sth.timestamp))

        if (old_sth.timestamp == new_sth.timestamp and
            old_sth.tree_size != new_sth.tree_size):
            # Issuing two different STHs for the same timestamp is illegal,
            # even if they are otherwise consistent.
            raise error.ConsistencyError("Inconsistency: different tree sizes "
                                         "for the same timestamp")
        if (old_sth.timestamp < new_sth.timestamp and
            old_sth.tree_size > new_sth.tree_size):
            raise error.ConsistencyError("Inconsistency: older tree has bigger "
                                         "size")
        return True

    @error.returns_true_or_raises
    def verify_sth_consistency(self, old_sth, new_sth, proof):
        """Verify consistency of two STHs.

        Verify the temporal consistency and consistency proof for two STH
        responses. Does not verify STH signatures.

        Args:
            old_sth: client_pb2.SthResponse() proto. The STH with the older
                timestamp must be supplied first.
            new_sth: client_pb2.SthResponse() proto.
            proof: a list of SHA256 audit nodes.

        Returns:
            True. The return value is enforced by a decorator and need not be
                checked by the caller.

        Raises:
            ConsistencyError: STHs are inconsistent
            ProofError: proof is invalid
            ValueError: "Older" STH is not older.
        """
        self.verify_sth_temporal_consistency(old_sth, new_sth)
        self.__merkle_verifier.verify_tree_consistency(
            old_sth.tree_size, new_sth.tree_size, old_sth.sha256_root_hash,
            new_sth.sha256_root_hash, proof)
        return True

    @error.returns_true_or_raises
    def verify_sct(self, sct, chain):
        """Verify the SCT over the X.509 certificate provided

        Args:
            sct: client_pb2.SignedCertificateTimestamp proto. Must have
                all fields present.
            chain: list of cert.Certificate instances. Begins with the
                certificate to be checked.

        Returns:
            True. The return value is enforced by a decorator and need not be
                checked by the caller.

        Raises:
            ct.crypto.error.EncodingError: failed to encode signature input,
                or decode the signature.
            ct.crypto.error.SignatureError: invalid signature.
            ct.crypto.error.IncompleteChainError: a certificate is missing
                from the chain.
        """

        if sct.version != ct_pb2.V1:
            raise error.UnsupportedVersionError("Cannot handle version: %s" %
                                                sct.version)
        entry = _create_dst_entry(sct, chain)
        signature_input = tls_message.encode(entry)

        return self._verify(signature_input, sct.signature.signature)


