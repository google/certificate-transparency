#!/usr/bin/env python

"""Tests for signer_ecdsa."""

import unittest

from ct.proto import client_pb2

from ct.crypto.signing import signer_ecdsa

PRIVATE_KEY_PEM = ("-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIFLw4uhuCruGKjrS9MoNeXFbypqZe+Sgh+EL1gnRn1d4oAoGCCqGSM49\n"
"AwEHoUQDQgAEmXg8sUUzwBYaWrRb+V0IopzQ6o3UyEJ04r5ZrRXGdpYM8K+hB0pX\n"
"rGRLI0eeWz+3skXrS0IO83AhA3GpRL6s6w==\n"
                   "-----END EC PRIVATE KEY-----\n")

class SignerEcdsaTest(unittest.TestCase):
    TEST_DATA = "test"
    TEST_DATA_SIGNATURE = (
            "3045022100a5a59ee846fef2e8020bf69cf538cbd61a2b3b3745508d7239dbc094b8"
            "da0c4c0220256db7344f3ecd13c2040542b5be5335311780b0ab024878352259c3e9"
            "a2fd4c").decode("hex")

    def testKnownSignatureValue(self):
        signer = signer_ecdsa.EcdsaSigner(PRIVATE_KEY_PEM)
        sig = signer.sign_raw(SignerEcdsaTest.TEST_DATA)
        self.assertEqual(SignerEcdsaTest.TEST_DATA_SIGNATURE, sig)

    def testSignatureIntoDigitallySigned(self):
        signer = signer_ecdsa.EcdsaSigner(PRIVATE_KEY_PEM)
        dsig = signer.sign(SignerEcdsaTest.TEST_DATA)
        self.assertEqual(dsig.hash_algorithm, client_pb2.DigitallySigned.SHA256)
        self.assertEqual(dsig.sig_algorithm, client_pb2.DigitallySigned.ECDSA)
        self.assertEqual(SignerEcdsaTest.TEST_DATA_SIGNATURE, dsig.signature)


if __name__ == '__main__':
    unittest.main()
