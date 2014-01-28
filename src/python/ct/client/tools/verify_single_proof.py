#!/usr/bin/env python
"""This utility fetches the proof for a single certificate by its hash."""

import struct
import sys

from ct.client import log_client
from ct.client import tls_message
from ct.crypto import cert
from ct.crypto import merkle
from ct.proto import client_pb2
from ct.proto import ct_pb2
import gflags

FLAGS = gflags.FLAGS

gflags.DEFINE_string("cert", None, "Certificate file (PEM format) to fetch a "
                     "proof for.")
gflags.DEFINE_string("sct", None, "SCT file (ProtoBuf) of said certificate.")
gflags.DEFINE_string("log_url", "ct.googleapis.com/pilot",
                     "URL of CT log.")


def create_leaf(timestamp, x509_cert_bytes):
    """Creates a MerkleTreeLeaf for the given X509 certificate."""
    leaf = client_pb2.MerkleTreeLeaf()
    leaf.version = client_pb2.V1
    leaf.leaf_type = client_pb2.TIMESTAMPED_ENTRY
    leaf.timestamped_entry.timestamp = timestamp
    leaf.timestamped_entry.entry_type = client_pb2.X509_ENTRY
    leaf.timestamped_entry.asn1_cert = x509_cert_bytes
    return tls_message.encode(leaf)

def run():
    """Fetch the proof for the supplied certificate."""
    client = log_client.LogClient(FLAGS.log_url)
    sth = client.get_sth()
    print '%d certificates in the log' % (sth.tree_size)
    cert_to_lookup = cert.Certificate.from_pem_file(FLAGS.cert)

    #TODO(eranm): Attempt fetching the SCT for this chain if none was given.
    cert_sct = ct_pb2.SignedCertificateTimestamp()
    cert_sct.ParseFromString(open(FLAGS.sct, 'rb').read())
    print 'SCT for cert:', cert_sct

    constructed_leaf = create_leaf(cert_sct.timestamp,
                                   cert_to_lookup.to_der())
    leaf_hash = merkle.TreeHasher().hash_leaf(constructed_leaf)
    print 'Assembled leaf hash:', leaf_hash.encode('hex')
    proof_from_hash = client.get_proof_by_hash(
            leaf_hash, sth.tree_size)
    #TODO(eranm): Verify the proof
    print 'Proof:', proof_from_hash

if __name__ == '__main__':
    sys.argv = FLAGS(sys.argv)
    run()
