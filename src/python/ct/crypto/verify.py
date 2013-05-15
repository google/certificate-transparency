import ecdsa
import hashlib
import io
import logging
import struct

from ct.proto import client_pb2, ct_pb2

class Error(Exception):
    pass

class FormatError(Error):
    pass

class UnsupportedAlgorithmError(Error):
    pass

class LogVerifier(object):
    def __init__(self, key_info):
        """Initialize from KeyInfo protocol buffer."""
        if key_info.type != client_pb2.KeyInfo.ECDSA:
            raise UnsupportedAlgorithmError("Key type %d not supported" %
                                            key_info.type)
        try:
            self.pubkey = ecdsa.VerifyingKey.from_pem(key_info.pem_key)
        except (ecdsa.der.UnexpectedDER, TypeError) as e:
            raise FormatError(e)

    def __repr__(self):
        return "%r(public key: %r)" % (self.__class__.__name__,
                                       self.pubkey.to_pem())

    def __str__(self):
        return "%s(public key: %s)" % (self.__class__.__name__,
                                       self.pubkey.to_pem())

    def _encode_sth_input(self, sth_response):
        if len(sth_response.sha256_root_hash) != 32:
            return None
        return struct.pack(">BBQQ32s", ct_pb2.V1, ct_pb2.TREE_HEAD,
                           sth_response.timestamp, sth_response.tree_size,
                           sth_response.sha256_root_hash)

    def _decode_signature(self, signature):
        sig_stream = io.BytesIO(signature)

        sig_prefix = sig_stream.read(2)
        if len(sig_prefix) != 2:
            logging.debug("Invalid algorithm prefix %s" %
                          sig_prefix.encode("hex"))
            return None
        hash_algo, sig_algo = struct.unpack(">BB", sig_prefix)
        if (hash_algo != ct_pb2.DigitallySigned.SHA256 or
            sig_algo != ct_pb2.DigitallySigned.ECDSA):
            logging.debug("Invalid algorithm(s) %d, %d" %
                          (hash_algo, sig_algo))
            return None

        length_prefix = sig_stream.read(2)
        if len(length_prefix) != 2:
            logging.debug("Invalid signature length prefix %s" %
                          length_prefix.encode("hex"))
            return None
        sig_length, = struct.unpack(">H", length_prefix)
        remaining = sig_stream.read()
        if len(remaining) != sig_length:
            logging.debug("Invalid signature length %d for signature %s with "
                          "length %d" % (sig_length, remaining.encode("hex"),
                                         len(remaining)))
            return None
        return remaining

    def _verify(self, signature_input, signature):
        try:
            return self.pubkey.verify(signature, signature_input,
                                      hashfunc=hashlib.sha256,
                                      sigdecode=ecdsa.util.sigdecode_der)
        except ecdsa.der.UnexpectedDER:
            logging.error("Invalid DER encoding for signature %s",
                          signature.encode("hex"))
            return False
        except ecdsa.keys.BadSignatureError:
            logging.error("Signature did not verify: %s",
                          signature.encode("hex"))
            return False

    def verify_sth(self, sth_response):
        """Verify the STH Response.
        Returns True or False.
        The response must have all fields present."""
        signature_input = self._encode_sth_input(sth_response)
        if signature_input is None:
            logging.error("Failed to encode STH input from %s", sth_response)
            return False
        signature = self._decode_signature(sth_response.tree_head_signature)
        if signature is None:
            logging.error("Failed to decode STH signature from %s",
                          sth_response)
            return False
        return self._verify(signature_input, signature)
