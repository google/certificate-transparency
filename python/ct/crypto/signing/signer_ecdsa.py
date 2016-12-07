"""ECDSA signatures suitable for CT logs"""
from ct.proto import client_pb2
import hashlib
import ecdsa

class EcdsaSigner(object):
    """Signs using deterministic ECDSA signatures."""

    def __init__(self, key_pem):
        """Creates a signer from a PEM-encoded ECDSA private key.

        Args:
            - key_pem: Private key, in PEM format.
        """
        self.__key = ecdsa.SigningKey.from_pem(key_pem)

    def sign_raw(self, data_to_sign):
        """Returns the raw signature bytes over |data_to_sign|.

        The signature is deterministic and output is DER encoded.
        """
        return self.__key.sign_deterministic(
                data_to_sign, hashfunc=hashlib.sha256,
                sigencode=ecdsa.util.sigencode_der)

    def sign(self, data_to_sign):
        """Returns a signature over |data_to_sign|.

        The returned value is a DigitallySigned protobuf instance with the
        right signature and hash algorithms set, in addition to the signature
        itself.
        """
        dsig = client_pb2.DigitallySigned()
        dsig.hash_algorithm = client_pb2.DigitallySigned.SHA256
        dsig.sig_algorithm = client_pb2.DigitallySigned.ECDSA
        dsig.signature = self.sign_raw(data_to_sign)
        return dsig
