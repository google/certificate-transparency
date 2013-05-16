#!/usr/bin/env python

import unittest

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

if __name__ == '__main__':
    unittest.main()
