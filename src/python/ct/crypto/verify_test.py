#!/usr/bin/env python

import mock
import unittest

from ct.crypto import error, verify
from ct.proto import client_pb2

class LogVerifierTest(unittest.TestCase):
    default_sth = client_pb2.SthResponse()
    default_sth.tree_size = 42
    default_sth.timestamp = 1348589667204
    default_sth.sha256_root_hash = (
        "18041bd4665083001fba8c5411d2d748e8abbfdcdfd9218cb02b68a78e7d4c23"
        ).decode("hex")

    default_sth.tree_head_signature = (
        "040300483046022100befd8060563763a5e49ba53e6443c13f7624fd6403178113736e"
        "16012aca983e022100f572568dbfe9a86490eb915c4ee16ad5ecd708fed35ed4e5cd1b"
        "2c3f087b4130").decode("hex")

    default_key_info = client_pb2.KeyInfo()
    default_key_info.type = client_pb2.KeyInfo.ECDSA
    default_key_info.pem_key = (
        "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES0AfBk"
        "jr7b8b19p5Gk8plSAN16wW\nXZyhYsH6FMCEUK60t7pem/ckoPX8hupuaiJzJS0ZQ0SEoJ"
        "GlFxkUFwft5g==\n-----END PUBLIC KEY-----\n")

    def test_verify_sth(self):
        verifier = verify.LogVerifier(LogVerifierTest.default_key_info)
        self.assertTrue(verifier.verify_sth(LogVerifierTest.default_sth))

    def test_verify_sth_fails_for_bad_signature(self):
        verifier = verify.LogVerifier(LogVerifierTest.default_key_info)
        default_sth = LogVerifierTest.default_sth

        for i in range(len(default_sth.tree_head_signature)):
            # Skip the bytes that encode ASN.1 lengths: this is covered in a
            # separate test
            if i == 5 or i == 7 or i == 42:
                continue
            sth = client_pb2.SthResponse()
            sth.CopyFrom(default_sth)
            sth.tree_head_signature = (
                default_sth.tree_head_signature[:i] +
                chr(ord(default_sth.tree_head_signature[i]) ^ 1) +
                default_sth.tree_head_signature[i+1:])
            # Encoding- or SignatureError, depending on whether the modified
            # byte is a content byte or not.
            self.assertRaises((error.EncodingError, error.SignatureError),
                              verifier.verify_sth, sth)

    def test_verify_sth_for_bad_asn1_length(self):
        verifier = verify.LogVerifier(LogVerifierTest.default_key_info)
        default_sth = LogVerifierTest.default_sth

        # The byte that encodes the length of the ASN.1 signature sequence
        i = 5

        # Decreasing the length truncates the sequence and causes a decoding
        # error.
        sth = client_pb2.SthResponse()
        sth.CopyFrom(default_sth)
        sth.tree_head_signature = (
            default_sth.tree_head_signature[:i] +
            chr(ord(default_sth.tree_head_signature[i]) - 1) +
            default_sth.tree_head_signature[i+1:])
        self.assertRaises(error.EncodingError, verifier.verify_sth, sth)

        # Increasing the length means there are not enough ASN.1 bytes left to
        # decode the sequence, however the ecdsa module silently slices it.
        # TODO(ekasper): contribute a patch to upstream and make the tests fail
        sth = client_pb2.SthResponse()
        sth.CopyFrom(default_sth)
        sth.tree_head_signature = (
            default_sth.tree_head_signature[:i] +
            chr(ord(default_sth.tree_head_signature[i]) + 1) +
            default_sth.tree_head_signature[i+1:])
        self.assertTrue(verifier.verify_sth(sth))

        # The byte that encodes the length of the first integer r in the
        # sequence (r, s). Modifying the length corrupts the second integer
        # offset and causes a decoding error.
        i = 7
        sth = client_pb2.SthResponse()
        sth.CopyFrom(default_sth)
        sth.tree_head_signature = (
            default_sth.tree_head_signature[:i] +
            chr(ord(default_sth.tree_head_signature[i]) - 1) +
            default_sth.tree_head_signature[i+1:])
        self.assertRaises(error.EncodingError, verifier.verify_sth, sth)

        sth = client_pb2.SthResponse()
        sth.CopyFrom(default_sth)
        sth.tree_head_signature = (
            default_sth.tree_head_signature[:i] +
            chr(ord(default_sth.tree_head_signature[i]) + 1) +
            default_sth.tree_head_signature[i+1:])
        self.assertRaises(error.EncodingError, verifier.verify_sth, sth)

        # The byte that encodes the length of the second integer s in the
        # sequence (r, s). Decreasing this length corrupts the integer, however
        # increased length is silently sliced, as above.
        i = 42
        sth = client_pb2.SthResponse()
        sth.CopyFrom(default_sth)
        sth.tree_head_signature = (
            default_sth.tree_head_signature[:i] +
            chr(ord(default_sth.tree_head_signature[i]) - 1) +
            default_sth.tree_head_signature[i+1:])
        self.assertRaises(error.EncodingError, verifier.verify_sth, sth)

        sth = client_pb2.SthResponse()
        sth.CopyFrom(default_sth)
        sth.tree_head_signature = (
            default_sth.tree_head_signature[:i] +
            chr(ord(default_sth.tree_head_signature[i]) + 1) +
            default_sth.tree_head_signature[i+1:])
        self.assertTrue(verifier.verify_sth(sth))

        # Trailing garbage is correctly detected.
        sth = client_pb2.SthResponse()
        sth.CopyFrom(default_sth)
        sth.tree_head_signature = (
            default_sth.tree_head_signature[:3] +
            # Correct outer length to include trailing garbage.
            chr(ord(default_sth.tree_head_signature[3]) + 1) +
            default_sth.tree_head_signature[4:]) + "\x01"
        self.assertRaises(error.EncodingError, verifier.verify_sth, sth)

    def test_verify_sth_consistency(self):
        old_sth = LogVerifierTest.default_sth
        new_sth = client_pb2.SthResponse()
        new_sth.CopyFrom(old_sth)
        new_sth.tree_size = old_sth.tree_size + 1
        new_sth.timestamp = old_sth.timestamp + 1
        new_sth.sha256_root_hash = "a new hash"
        proof = ["some proof the mock does not care about"]

        mock_merkle_verifier = mock.Mock()
        mock_merkle_verifier.verify_tree_consistency.return_value = True

        verifier = verify.LogVerifier(LogVerifierTest.default_key_info,
                                      mock_merkle_verifier)
        self.assertTrue(verifier.verify_sth_consistency(old_sth, new_sth,
                                                        proof))
        mock_merkle_verifier.verify_tree_consistency.assert_called_once_with(
            old_sth.tree_size, new_sth.tree_size, old_sth.sha256_root_hash,
            new_sth.sha256_root_hash, proof)

    def test_verify_sth_temporal_consistency(self):
        old_sth = LogVerifierTest.default_sth
        new_sth = client_pb2.SthResponse()
        new_sth.CopyFrom(old_sth)
        new_sth.tree_size = old_sth.tree_size + 1
        new_sth.timestamp = old_sth.timestamp + 1

        # Merkle verifier is never used so simply set to None
        verifier = verify.LogVerifier(LogVerifierTest.default_key_info,
                                      None)

        # Note we do not care about root hash inconsistency here.
        self.assertTrue(verifier.verify_sth_temporal_consistency(
                old_sth, new_sth))

    def test_verify_sth_temporal_consistency_equal_timestamps(self):
        old_sth = LogVerifierTest.default_sth
        new_sth = client_pb2.SthResponse()
        new_sth.CopyFrom(old_sth)
        new_sth.tree_size = old_sth.tree_size + 1

        # Merkle verifier is never used so simply set to None
        verifier = verify.LogVerifier(LogVerifierTest.default_key_info,
                                      None)

        self.assertRaises(error.ConsistencyError,
                          verifier.verify_sth_temporal_consistency,
                old_sth, new_sth)

        new_sth.tree_size = old_sth.tree_size - 1
        self.assertRaises(error.ConsistencyError,
                          verifier.verify_sth_temporal_consistency,
                old_sth, new_sth)

        # But identical STHs are OK
        self.assertTrue(verifier.verify_sth_temporal_consistency(
                old_sth, old_sth))

    def test_verify_sth_temporal_consistency_reversed_timestamps(self):
        old_sth = LogVerifierTest.default_sth
        new_sth = client_pb2.SthResponse()
        new_sth.CopyFrom(old_sth)
        new_sth.timestamp = old_sth.timestamp + 1
        new_sth.tree_size = old_sth.tree_size + 1

        # Merkle verifier is never used so simply set to None
        verifier = verify.LogVerifier(LogVerifierTest.default_key_info,
                                      None)

        self.assertRaises(ValueError,
                          verifier.verify_sth_temporal_consistency,
                new_sth, old_sth)

    def test_verify_sth_temporal_consistency_newer_tree_is_smaller(self):
        old_sth = LogVerifierTest.default_sth
        new_sth = client_pb2.SthResponse()
        new_sth.CopyFrom(old_sth)
        new_sth.timestamp = old_sth.timestamp + 1
        new_sth.tree_size = old_sth.tree_size - 1

        # Merkle verifier is never used so simply set to None
        verifier = verify.LogVerifier(LogVerifierTest.default_key_info,
                                      None)

        self.assertRaises(error.ConsistencyError,
                          verifier.verify_sth_temporal_consistency,
                old_sth, new_sth)

    def test_verify_sth_consistency_invalid_proof(self):
        old_sth = LogVerifierTest.default_sth
        new_sth = client_pb2.SthResponse()
        new_sth.CopyFrom(old_sth)
        new_sth.tree_size = old_sth.tree_size + 1
        new_sth.timestamp = old_sth.timestamp + 1
        new_sth.sha256_root_hash = "a new hash"
        proof = ["some proof the mock does not care about"]

        mock_merkle_verifier = mock.Mock()
        mock_merkle_verifier.verify_tree_consistency.side_effect = (
            error.ConsistencyError("Evil"))

        verifier = verify.LogVerifier(LogVerifierTest.default_key_info,
                                      mock_merkle_verifier)
        self.assertRaises(error.ConsistencyError,
                          verifier.verify_sth_consistency,
                          old_sth, new_sth, proof)

if __name__ == '__main__':
    unittest.main()
