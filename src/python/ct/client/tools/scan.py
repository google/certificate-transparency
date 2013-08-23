#!/usr/bin/env python

import io
import struct
import sys

import gflags

from ct.client import log_client
from ct.crypto import cert
from ct.crypto import error

FLAGS = gflags.FLAGS


class Error(Exception):
    pass

# Temporary glue code
# TODO(ekasper): define the constants properly in the decoder.
V1 = 0
TIMESTAMPED_ENTRY = 0
X509_ENTRY, PRECERT_ENTRY = range(2)

# TODO(ekasper): replace with a proper TLS decoder.
def decode_leaf_input(leaf_input):
    leaf_bytes = io.BytesIO(leaf_input)

    version = leaf_bytes.read(1)
    if not version:
        raise Error("Input too short")
    version, = struct.unpack(">B", version)
    # TODO(ekasper): replace with enums
    if version != V1:
        raise Error("Unsupported version %d" % version)

    leaf_type = leaf_bytes.read(1)
    if not leaf_type:
        raise Error("Input too short")
    leaf_type, = struct.unpack(">B", leaf_type)
    if leaf_type != 0:
        raise Error("Unsupported leaf_type %d" % leaf_type)

    timestamp = leaf_bytes.read(8)
    if len(timestamp) < 8:
        raise Error("Input too short")
    timestamp, = struct.unpack(">Q", timestamp)

    entry_type = leaf_bytes.read(2)
    if len(entry_type) < 2:
        raise Error("Input too short")
    entry_type, = struct.unpack(">H", entry_type)
    if entry_type != X509_ENTRY and entry_type != PRECERT_ENTRY:
        raise Error("Unsupported entry_type %d" % entry_type)

    cert_length_prefix = leaf_bytes.read(3)
    if len(cert_length_prefix) != 3:
        raise Error("Input too short")
    cert_length, = struct.unpack(">I", '\x00' + cert_length_prefix)

    cert = leaf_bytes.read(cert_length)
    if len(cert) < cert_length:
        raise Error("Input too short")

    extensions_length_prefix = leaf_bytes.read(2)
    if len(extensions_length_prefix) != 2:
        raise Error("Input too short")
    extensions_length, = struct.unpack(">H", extensions_length_prefix)

    extensions = leaf_bytes.read(extensions_length)
    if len(extensions) != extensions_length:
        raise Error("Input too short")

    if leaf_bytes.read():
        raise Error("Input too long")

    return entry_type, cert

def match(certificate):
    # Fill this in with your match criteria, e.g.
    #
    # return "google" in certificate.subject_name().lower()
    #
    return True

def scan():
    client = log_client.LogClient(log_client.Requester(
            "ct.googleapis.com/pilot"))
    sth = client.get_sth()
    print "got sth: %s" % sth

    entries = client.get_entries(0, sth.tree_size - 1)
    scanned = 0
    for entry in entries:
        entry_type, der_cert = decode_leaf_input(entry.leaf_input)
        if entry_type == PRECERT_ENTRY:
            print "Found precert: %s" % der_cert.encode("hex")
            raw_input("press Enter to continue")
        else:
            try:
                c = cert.Certificate(der_cert)
            except error.Error as e:
                print "Error while parsing entry no %d:\n%s" % (scanned, e)
                print "Raw entry:\n%s" % der_cert.encode("hex")
                raw_input("press Enter to continue")
            else:
                if match(c):
                    print "Found matching certificate"
                    print c
                    raw_input("press Enter to continue")
        scanned += 1
        if not scanned % 1000:
            print "Scanned %d entries" % (scanned)

if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
    scan()
