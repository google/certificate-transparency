"""Test meta-data and configuration."""

import os

CRYPTO_TEST_DATA_DIR = "ct/crypto/testdata/"

def get_test_file_path(filename):
    return os.path.join(os.curdir, CRYPTO_TEST_DATA_DIR, filename)
