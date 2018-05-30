from ct.crypto import error
from ct.crypto import pem
from ct.proto import client_pb2

import cryptography
from cryptography.hazmat.backends import default_backend as crypto_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

class EcdsaVerifier(object):
    """Verifies ECDSA signatures."""

    # The signature algorithm used for this public key."""
    SIGNATURE_ALGORITHM = client_pb2.DigitallySigned.ECDSA
    # The hash algorithm used for this public key."""
    HASH_ALGORITHM = client_pb2.DigitallySigned.SHA256

    def __init__(self, key_info):
        """Creates a verifier that uses a PEM-encoded ECDSA public key.

        Args:
        - key_info: KeyInfo protobuf message

        Raises:
        - PemError: If the key has an invalid encoding
        - UnsupportedAlgorithmError: If the key uses an unsupported algorithm
        """
        if (key_info.type != client_pb2.KeyInfo.ECDSA):
            raise error.UnsupportedAlgorithmError(
                "Expected ECDSA key, but got key type %d" % key_info.type)

        pem_key = str(key_info.pem_key)

        try:
            self.__key = crypto_backend().load_pem_public_key(pem_key)
        except ValueError as e:
            raise pem.PemError(e)
        except cryptography.exceptions.UnsupportedAlgorithm as e:
            raise error.UnsupportedAlgorithmError(e)

    def __repr__(self):
        key_pem = self.__key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

        return "%s(public key: %r)" % (self.__class__.__name__, key_pem)

    @error.returns_true_or_raises
    def verify(self, signature_input, signature):
        """Verifies the signature was created by the owner of the public key.

        Args:
        - signature_input: The data that was originally signed.
        - signature: An ECDSA SHA256 signature.

        Returns:
        - True if the signature verifies.

        Raises:
        - error.SignatureError: If the signature fails verification.
        """
        try:
            self.__key.verify(signature, signature_input,
                              ec.ECDSA(hashes.SHA256()))
        except cryptography.exceptions.InvalidSignature:
            raise error.SignatureError("Signature did not verify: %s" %
                                       signature.encode("hex"))

        return True

