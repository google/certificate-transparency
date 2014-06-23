#!/usr/bin/env python

import sys

import gflags

from ct.client import scanner

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("multi", 1, "Number of cert parsing processes to use in "
                      "addition to the main process and the network process.")


def match(certificate, entry_type, extra_data, certificate_index):
    # Fill this in with your match criteria, e.g.
    #
    # return "google" in certificate.subject_name().lower()
    #
    # NB: for precertificates, issuer matching may not work as expected
    # when the precertificate has been issued by the special-purpose
    # precertificate signing certificate.
    return True


def run():
    res = scanner.scan_log(
        match, "https://ct.googleapis.com/pilot", FLAGS.multi)
    print "Scanned %d, %d matched and %d failed strict or partial parsing" % (
        res.total, res.matches, res.errors)


if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
    run()
