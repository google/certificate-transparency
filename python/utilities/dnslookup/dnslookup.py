#!/usr/bin/env python

# Implement DNS inclusion proof checking, see [TBD].
#
# Unfortunately, getting at the SCTs in general is hard in Python, so this
# does not start with an SSL connection, but instead fetches a log entry by
# index and then verifies the proof over DNS.

# You will need to install DNSPython (http://www.dnspython.org/)

import base64
import dns.resolver
import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
import urllib2

ALL_LOGS_URL = 'https://www.certificate-transparency.org/known-logs/all_logs_list.json'

basepath = os.path.dirname(sys.argv[0])
sys.path.append(os.path.join(basepath, '../../../python'))
from ct.crypto import merkle, verify
from ct.proto import ct_pb2, client_pb2

ctpath = os.path.join(basepath, '../../../cpp/client/ct')
libpath = os.path.join(basepath, '../../../../install/lib')

class CTDNSLookup:
    def __init__(self, domain, verifier, nameservers, port = 53):
        self.verifier = verifier
        self.domain = domain
        self.resolver = dns.resolver.get_default_resolver()
        self.resolver.nameservers = nameservers
        self.resolver.port = port

    def Get(self, name):
        logging.info('get %s' % name)
        answers = self.resolver.query(name, 'TXT')
        assert answers.rdtype == dns.rdatatype.TXT
        return answers

    def GetOne(self, name):
        name += '.%s' % self.domain
        answers = self.Get(name)
        assert len(answers) == 1
        txt = answers[0]
        assert len(txt.strings) == 1
        return txt.strings[0]

    def GetSTH(self):
        sth_str = self.GetOne('sth')
        sth = client_pb2.SthResponse()
        parts = str(sth_str).split('.')
        sth.tree_size = int(parts[0])
        sth.timestamp = int(parts[1])
        sth.sha256_root_hash = base64.b64decode(parts[2])
        sth.tree_head_signature = base64.b64decode(parts[3])

        self.verifier.verify_sth(sth)

        return sth

    def GetEntry(self, level, index, size):
        return self.GetOne('%d.%d.%d.tree' % (level, index, size))

    def GetIndexFromHash(self, hash):
        return self.GetOne('%s.hash' % base64.b32encode(hash).replace('=', ''))

if __name__ == '__main__':
    logging.basicConfig(level="INFO")

    index = sys.argv[1]

    keypem = ("-----BEGIN PUBLIC KEY-----\n"
              "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p\n"
              "3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J\n"
              "5APC2em4JlvR8EEEFMoA==\n"
              "-----END PUBLIC KEY-----\n")
    logurl = 'http://ct.googleapis.com/pilot';
    logdns = 'pilot.ct.googleapis.com'

    response = urllib2.urlopen('%s/ct/v1/get-entries?start=%s&end=%s'
                               %  (logurl, index, index))
    j = response.read()
    j = json.loads(j)
    leaf_input = j['entries'][0]['leaf_input']
    logging.info('leaf = %s' % leaf_input)
    leaf = base64.b64decode(leaf_input)
    leaf_hash = hashlib.sha256(chr(0) + leaf).digest()

    keyinfo = client_pb2.KeyInfo()
    keyinfo.type = keyinfo.ECDSA
    keyinfo.pem_key =  keypem
    log_verifier = verify.LogVerifier(keyinfo)

    lookup = CTDNSLookup(logdns, log_verifier, ['8.8.8.8'])
    sth = lookup.GetSTH()
    logging.info('sth = %s' % sth)

    logging.info('hash = %s' % base64.b64encode(leaf_hash))
    verifier = merkle.MerkleVerifier()
    index = int(index)
    audit_path = []
    prev = None
    apl = verifier.audit_path_length(index, sth.tree_size)
    for level in range(0, apl):
        h = lookup.GetEntry(level, index, sth.tree_size)
        logging.info('hash = %s' % base64.b64encode(h))
        audit_path.append(h[:32])

        if prev:
            if level < apl - 6:
                assert prev[32:] == h[:-32]
            else:
                assert prev[32:] == h
        else:
            assert len(h) == 32 * min(7, apl)

        prev = h

    logging.info('path = %s' % map(base64.b64encode, audit_path))

    assert verifier.verify_leaf_hash_inclusion(leaf_hash, index, audit_path,
                                               sth)

    hash_info = lookup.GetIndexFromHash(leaf_hash)
    assert hash_info == str(index)
