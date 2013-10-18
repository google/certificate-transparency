#!/usr/bin/env python

import hashlib
import unittest

from ct.crypto import error
from ct.crypto import merkle


class TreeHasherTest(unittest.TestCase):
    sha256_empty_hash = ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495"
                         "991b7852b855")
    sha256_leaves = [
        ("",
         "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
        ("101112131415161718191a1b1c1d1e1f",
         "3bfb960453ebaebf33727da7a1f4db38acc051d381b6da20d6d4e88f0eabfd7a")
        ]
    sha256_nodes = [
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
         "1a378704c17da31e2d05b6d121c2bb2c7d76f6ee6fa8f983e596c2d034963c57")]

    # array of bytestrings of the following literals in hex
    test_vector_leaves = ["".join(chr(int(n, 16)) for n in s.split()) for s in [
        "",
        "00",
        "10",
        "20 21",
        "30 31",
        "40 41 42 43",
        "50 51 52 53 54 55 56 57",
        "60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f",
    ]]

    test_vector_hashes = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ]

    def test_empty_hash(self):
        hasher = merkle.TreeHasher()
        self.assertEqual(hasher.hash_empty().encode("hex"),
                         TreeHasherTest.sha256_empty_hash)

    def test_hash_leaves(self):
        hasher = merkle.TreeHasher()
        for leaf, val in TreeHasherTest.sha256_leaves:
            self.assertEqual(hasher.hash_leaf(leaf.decode("hex")).encode("hex"),
                             val)

    def test_hash_children(self):
        hasher = merkle.TreeHasher()
        for left, right, val in  TreeHasherTest.sha256_nodes:
            self.assertEqual(hasher.hash_children(
                left.decode("hex"), right.decode("hex")).encode("hex"), val)

    def test_hash_full_invalid_index(self):
        hasher = merkle.TreeHasher()
        self.assertRaises(IndexError, hasher._hash_full, "abcd", -5, -1)
        self.assertRaises(IndexError, hasher._hash_full, "abcd", -1, 1)
        self.assertRaises(IndexError, hasher._hash_full, "abcd", 1, 5)
        self.assertRaises(IndexError, hasher._hash_full, "abcd", 2, 1)

    def test_hash_full_empty(self):
        hasher = merkle.TreeHasher()
        for i in xrange(0, 5):
            self.assertEqual(hasher._hash_full("abcd", i, i)[0].encode("hex"),
                              TreeHasherTest.sha256_empty_hash)

    def test_hash_full_tree(self):
        hasher = merkle.TreeHasher()
        self.assertEqual(hasher.hash_full_tree([]), hasher.hash_empty())
        l = iter(hasher.hash_leaf(c) for c in "abcde").next
        h = hasher.hash_children
        root_hash = h(h(h(l(), l()), h(l(), l())), l())
        self.assertEqual(hasher.hash_full_tree("abcde"), root_hash)

    def test_hash_full_tree_test_vector(self):
        hasher = merkle.TreeHasher()
        for i in xrange(len(TreeHasherTest.test_vector_leaves)):
            test_vector = TreeHasherTest.test_vector_leaves[:i+1]
            expected_hash = TreeHasherTest.test_vector_hashes[i].decode("hex")
            self.assertEqual(hasher.hash_full_tree(test_vector), expected_hash)


class HexTreeHasher(object):
    def __init__(self, hashfunc=hashlib.sha256):
        self.hasher = merkle.TreeHasher(hashfunc)

    def hash_empty(self):
        return self.hasher.hash_empty().encode("hex")

    def hash_leaf(self, data):
        return self.hasher.hash_leaf(data.decode("hex")).encode("hex")

    def hash_children(self, left, right):
        return self.hasher.hash_children(left.decode("hex"),
                                         right.decode("hex")).encode("hex")


class MerkleVerifierTest(unittest.TestCase):
    # (old_tree_size, new_tree_size, old_root, new_root, proof)
    # Test vectors lifted from the C++ branch.
    sha256_proofs = [
        (1, 1,
         "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
         "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
         []),
        (1, 8,
         "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
         "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
         ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
          "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
          "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"]),
        (6, 8,
         "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
         "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
         ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
          "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
          "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]),
        (2, 5,
         "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
         "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
         ["5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
          "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"])
        ]

    def setUp(self):
        self.verifier = merkle.MerkleVerifier(HexTreeHasher())

    def test_verify_tree_consistency(self):
        verifier = merkle.MerkleVerifier(HexTreeHasher())
        for test_vector in  MerkleVerifierTest.sha256_proofs:
            self.assertTrue(verifier.verify_tree_consistency(*test_vector))

    def test_verify_tree_consistency_always_accepts_empty_tree(self):
        verifier = merkle.MerkleVerifier(HexTreeHasher())
        # Give some bogus proof too; it should be ignored.
        self.assertTrue(verifier.verify_tree_consistency(
            0, 1,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"]
            ))

    def test_verify_tree_consistency_for_equal_tree_sizes(self):
        verifier = merkle.MerkleVerifier(HexTreeHasher())
        # Equal tree sizes and hashes, and a bogus proof that should be ignored.
        self.assertTrue(verifier.verify_tree_consistency(
            3, 3,
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"]
            ))

        # Equal tree sizes but different hashes.
        self.assertRaises(
            error.ConsistencyError, verifier.verify_tree_consistency, 3, 3,
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01e",
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            [])

    def test_verify_tree_consistency_newer_tree_is_smaller(self):
        verifier = merkle.MerkleVerifier(HexTreeHasher())
        self.assertRaises(
            ValueError, verifier.verify_tree_consistency, 5, 2,
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            ["5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
             "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"]
            )

    def test_verify_tree_consistency_proof_too_short(self):
        verifier = merkle.MerkleVerifier(HexTreeHasher())
        self.assertRaises(
            error.ProofError, verifier.verify_tree_consistency, 6, 8,
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
            ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
             "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"]
            )

    def test_verify_tree_consistency_bad_second_hash(self):
        verifier = merkle.MerkleVerifier(HexTreeHasher())
        # A bit has been flipped in the second hash.
        self.assertRaises(
            error.ProofError, verifier.verify_tree_consistency, 6, 8,
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604329",
            ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
             "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
             "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]
            )

    def test_verify_tree_consistency_both_hashes_bad(self):
        verifier = merkle.MerkleVerifier(HexTreeHasher())
        # A bit has been flipped in both hashes.
        self.assertRaises(
            error.ProofError, verifier.verify_tree_consistency, 6, 8,
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ee",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604329",
            ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
             "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
             "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]
            )

    def test_verify_tree_consistency_bad_first_hash(self):
        verifier = merkle.MerkleVerifier(HexTreeHasher())
        # A bit has been flipped in the first hash.
        self.assertRaises(
            error.ConsistencyError, verifier.verify_tree_consistency, 6, 8,
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ee",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
            ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
             "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
             "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]
            )

if __name__ == "__main__":
    unittest.main()
