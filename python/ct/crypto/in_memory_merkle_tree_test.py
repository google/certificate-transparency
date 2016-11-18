#!/usr/bin/env python

"""Tests for InMemoryMerkleTree."""

from collections import namedtuple

import unittest

from ct.crypto import in_memory_merkle_tree
from ct.crypto import merkle

PathTestVector = namedtuple("PathTestVector",
    ["leaf", "tree_size_snapshot", "path_length", "path"])

ConsistencyTestVector = namedtuple("ConsistencyTestVector",
    ["snapshot_1", "snapshot_2", "proof"])

DummySTH = namedtuple("DummySTH", ["tree_size", "sha256_root_hash"])


def decode_hex_strings_list(hex_strings_list):
    """Decodes a list of hex strings."""
    return [t.decode("hex") for t in hex_strings_list]

# Leaves of a sample tree of size 8.
TEST_VECTOR_DATA = decode_hex_strings_list([
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
])

PRECOMPUTED_PATH_TEST_VECTORS = [
    PathTestVector(0, 0, 0, []),
    PathTestVector(0, 1, 0, []),
    PathTestVector(0, 8, 3, decode_hex_strings_list(
            ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
             "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
             "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"]
    )),
    PathTestVector(5, 8, 3, decode_hex_strings_list(
            ["bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
             "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
             "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]
    )),
    PathTestVector(2, 3, 1, decode_hex_strings_list(
            ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"]
    )),
    PathTestVector(1, 5, 3, decode_hex_strings_list(
            ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
             "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
             "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"]
    ))]

PRECOMPUTED_PROOF_TEST_VECTORS = [
    ConsistencyTestVector(1, 1, []),
    ConsistencyTestVector(1, 8, decode_hex_strings_list(
            ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
             "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
             "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"]
    )),
    ConsistencyTestVector(6, 8, decode_hex_strings_list(
            ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
             "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
             "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]
    )),
    ConsistencyTestVector(2, 5, decode_hex_strings_list(
            ["5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
             "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"]
    )),
    ]


class InMemoryMerkleTreeTest(unittest.TestCase):
    """Tests for InMemoryMerkleTree."""

    def test_tree_incremental_root_hash(self):
        """Test root hash calculation.

        Test that root hash is calculated correctly when leaves are added
        incrementally.
        """
        tree = in_memory_merkle_tree.InMemoryMerkleTree([])
        hasher = merkle.TreeHasher()
        for i in range(len(TEST_VECTOR_DATA)):
            tree.add_leaf(TEST_VECTOR_DATA[i])
            self.assertEqual(
                    tree.get_root_hash(),
                    hasher.hash_full_tree(TEST_VECTOR_DATA[0:i+1]))

    def test_tree_snapshot_root_hash(self):
        """Test root hash calculation.

        Test that root hash is calculated correctly when all leaves are added
        at once.
        """
        tree = in_memory_merkle_tree.InMemoryMerkleTree(TEST_VECTOR_DATA)
        hasher = merkle.TreeHasher()
        for i in range(len(TEST_VECTOR_DATA)):
            self.assertEqual(
                    tree.get_root_hash(i),
                    hasher.hash_full_tree(TEST_VECTOR_DATA[0:i]))

    def test_tree_inclusion_proof_precomputed(self):
        """Test inclusion proof generation.

        Test inclusion proof generation correctness test for known-good
        proofs.
        """
        tree = in_memory_merkle_tree.InMemoryMerkleTree(TEST_VECTOR_DATA)
        verifier = merkle.MerkleVerifier()
        for v in PRECOMPUTED_PATH_TEST_VECTORS:
            audit_path = tree.get_inclusion_proof(v.leaf, v.tree_size_snapshot)
            self.assertEqual(len(audit_path), v.path_length)
            self.assertEqual(audit_path, v.path)

            leaf_data = TEST_VECTOR_DATA[v.leaf]
            leaf_hash = merkle.TreeHasher().hash_leaf(leaf_data)
            dummy_sth = DummySTH(v.tree_size_snapshot,
                tree.get_root_hash(v.tree_size_snapshot))

            if v.tree_size_snapshot > 0:
                verifier.verify_leaf_hash_inclusion(
                        leaf_hash, v.leaf, audit_path, dummy_sth)

    def test_tree_inclusion_proof_generated(self):
        """Test inclusion proof generation.

        Test inclusion proof generation correctness for generated proofs.
        """
        leaves = []
        leaf_hashes = []
        hasher = merkle.TreeHasher()
        for i in range(128):
            leaves.append(chr(i) * 32)
            leaf_hashes.append(hasher.hash_leaf(leaves[-1]))

        tree = in_memory_merkle_tree.InMemoryMerkleTree(leaves)
        verifier = merkle.MerkleVerifier()

        for i in range(1, tree.tree_size()):
            for j in range(i):
                audit_path = tree.get_inclusion_proof(j, i)
                dummy_sth = DummySTH(i, tree.get_root_hash(i))
                verifier.verify_leaf_hash_inclusion(
                        leaf_hashes[j], j, audit_path, dummy_sth)

    def test_tree_consistency_proof_precomputed(self):
        """Test consistency proof generation.

        Test Consistency proof generation correctness test for known-good
        proofs.
        """
        tree = in_memory_merkle_tree.InMemoryMerkleTree(TEST_VECTOR_DATA)
        for v in PRECOMPUTED_PROOF_TEST_VECTORS:
            consistency_proof = tree.get_consistency_proof(
                    v.snapshot_1, v.snapshot_2)
            self.assertEqual(consistency_proof, v.proof)

    def test_tree_consistency_proof_generated(self):
        """Test consistency proof generation.

        Consistency proof generation correctness test for generated proofs.
        """
        leaves = []
        for i in range(128):
            leaves.append(chr(i) * 32)

        tree = in_memory_merkle_tree.InMemoryMerkleTree(leaves)
        verifier = merkle.MerkleVerifier()

        for i in range(1, tree.tree_size()):
            for j in range(i):
                consistency_proof = tree.get_consistency_proof(j, i)
                self.assertTrue(verifier.verify_tree_consistency(
                        j, i, tree.get_root_hash(j), tree.get_root_hash(i),
                        consistency_proof))

    def test_tree_get_root_hash_invalid_size(self):
        """Test handling of bad inputs to get root hash.

        Test that an assertion is raised for invalid tree size passed
        into get_root_hash.
        """
        tree = in_memory_merkle_tree.InMemoryMerkleTree(TEST_VECTOR_DATA)
        self.assertRaises(ValueError, tree.get_root_hash, tree.tree_size() + 3)

    def test_tree_inclusion_proof_bad_indices(self):
        """Test handling of bad inputs into get inclusion proof.

        Test that an assertion is raised for invalid tree sizes or invalid
        leaf indices are passed into get_inclusion_proof.
        """
        tree = in_memory_merkle_tree.InMemoryMerkleTree(TEST_VECTOR_DATA)
        n = tree.tree_size()
        # Tree size too large
        self.assertRaises(ValueError, tree.get_inclusion_proof, 0, n + 3)
        # Leaf index too large
        self.assertRaises(ValueError,
                          tree.get_inclusion_proof, n + 3, n - 1)

    def test_tree_consistency_proof_bad_indices(self):
        """Test handling of bad inputs into get consistency proof.

        Test that an assertion is raised for invalid tree sizes passed
        into get_consistency_proof.
        """
        tree = in_memory_merkle_tree.InMemoryMerkleTree(TEST_VECTOR_DATA)
        n = tree.tree_size()
        # 2nd tree size too large
        self.assertRaises(ValueError, tree.get_consistency_proof, 1, n + 3)
        # 1st tree size > 2nd tree size
        self.assertRaises(ValueError,
                          tree.get_consistency_proof, n - 1, n - 3)

if __name__ == "__main__":
    unittest.main()
