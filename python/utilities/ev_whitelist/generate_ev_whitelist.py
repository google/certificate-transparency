#!/usr/bin/env python
"""Generates a list of hashes of EV certificates found in a log."""

import hashlib
import pickle
import os
import sys

import ev_metadata
import gflags

from ct.client import scanner
from ct.crypto import cert
from ct.proto import client_pb2

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("hash_trim", 8, "Number of bytes of the SHA-256 digest "
                      "to use in the whitelist.")

gflags.DEFINE_integer("multi", 2, "Number of cert fetching and parsing "
                      "processes to use, in addition to the main process.")

gflags.DEFINE_string("output", "ev_whitelist.bin",
                     "Output file containing the list of EV cert hashes. "
                     "The output is fixed-sized records of hash_trim bytes per "
                     "hash.")

gflags.DEFINE_string("output_directory", None,
                     "Output directory for individual EV certificates. "
                     "If provided, individual EV certs will be written there.")


def calculate_certificate_hash(certificate):
    """Hash the input's DER representation and trim it."""
    hasher = hashlib.sha256(certificate.to_der())
    return hasher.digest()[0:FLAGS.hash_trim]


def find_matching_policy(certificate):
    """Returns the certificate's EV policy OID, if exists."""
    try:
        for policy in certificate.policies():
            if policy['policyIdentifier'] in ev_metadata.EV_POLICIES:
                return policy['policyIdentifier']
    except cert.CertificateError:
        pass
    return None


def does_root_match_policy(policy_oid, cert_chain):
    """Returns true if the fingerprint of the root certificate matches the
    expected fingerprint for this EV policy OID."""
    root_fingerprint = hashlib.sha1(cert_chain[-1]).digest()
    return root_fingerprint in ev_metadata.EV_POLICIES[policy_oid]


def _write_cert_and_chain(certificate, extra_data, certificate_index):
    """Writes the certificate and its chain to files for later analysis."""
    open(
        os.path.join(FLAGS.output_directory,
                     "cert_%d.der" % certificate_index), "wb"
        ).write(certificate.to_der())

    pickle.dump(
        list(extra_data.certificate_chain),
        open(os.path.join(FLAGS.output_directory,
                          "cert_%d_extra_data.pickle" % certificate_index),
             "wb"))

def _ev_match(certificate, entry_type, extra_data, certificate_index):
    """Matcher function for the scanner. Returns the certificate's hash if
    it is a valid EV certificate, None otherwise."""
    # Only generate whitelist for non-precertificates. It is expected that if
    # a precertificate was submitted then the issued SCT would be embedded
    # in the final certificate.
    if entry_type != client_pb2.X509_ENTRY:
        return None
    if certificate.is_expired():
        return None
    matching_policy = find_matching_policy(certificate)
    if not matching_policy:
        return None

    if not does_root_match_policy(
            matching_policy, extra_data.certificate_chain):
        return None

    # Matching certificate
    if FLAGS.output_directory:
        _write_cert_and_chain(certificate, extra_data, certificate_index)

    return calculate_certificate_hash(certificate)


def generate_ev_cert_hashes_from_log(log_url):
    """Scans the given log and generates a list of hashes for all EV
    certificates in it.

    Returns a tuple of (scan_results, hashes_list)"""
    ev_hashes = set()
    def add_hash(cert_hash):
        """Store the hash. Always called from the main process, so safe."""
        ev_hashes.add(cert_hash)
    res = scanner.scan_log(_ev_match, log_url, FLAGS.multi, add_hash)
    return (res, ev_hashes)

def main():
    """Scan and save results to a file."""
    if FLAGS.output_directory and not os.path.exists(FLAGS.output_directory):
        os.mkdir(FLAGS.output_directory)
    res, hashes_set = generate_ev_cert_hashes_from_log(
        "https://ct.googleapis.com/pilot")
    print "Scanned %d, %d matched and %d failed strict or partial parsing" % (
        res.total, res.matches, res.errors)
    print "There are %d EV hashes." % (len(hashes_set))
    with open(FLAGS.output, "wb") as hashes_file:
        hashes_list = list(hashes_set)
        hashes_list.sort()
        for trimmed_hash in hashes_list:
            hashes_file.write(trimmed_hash)


if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
    main()
