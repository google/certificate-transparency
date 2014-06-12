import base64
import dns.resolver
import dns.rdatatype
import math
import os
import random
import shlex
import subprocess
import sys

basepath = os.path.dirname(sys.argv[0])

sys.path.append(os.path.join(basepath, '../../python'))
from ct.crypto import merkle
from ct.proto import ct_pb2

class CTDNSLookup:
    def __init__(self, nameservers, port):
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = nameservers
        self.resolver.port = port

    def Get(self, name):
        answers = self.resolver.query(name, 'TXT')
        assert answers.rdtype == dns.rdatatype.TXT
        return answers

    def GetOne(self, name):
        answers = self.Get(name)
        assert len(answers) == 1
        txt = answers[0]
        assert len(txt.strings) == 1
        return txt.strings[0]

    def GetSTH(self):
        sth_str = self.GetOne('sth.example.com')
        sth = ct_pb2.SignedTreeHead()
        parts = str(sth_str).split('.')
        sth.tree_size = int(parts[0])
        sth.timestamp = int(parts[1])
        sth.sha256_root_hash = base64.b64decode(parts[2])
        #FIXME(benl): decompose signature into its parts
        #sth.signature = base64.b64decode(parts[3])
        return sth

    def GetEntry(self, level, index, size):
        return self.GetOne(str(level) + '.' + str(index) + '.' + str(size)
                           + '.tree.example.com')

    def GetLeafHash(self, index):
        return self.GetOne(str(index) + '.leafhash.example.com')

class DNSServerRunner:
    def Run(self, cmd):
        args = shlex.split(cmd)
        self.proc = subprocess.Popen(args)

server_cmd = basepath + "/ct-dns-server --port=1111 --domain=example.com. --db=/tmp/ct"
runner = DNSServerRunner()
runner.Run(server_cmd)

lookup = CTDNSLookup(['127.0.0.1'], 1111)
sth = lookup.GetSTH()
print "sth =", sth
print "size =", sth.tree_size

# Verify a random entry
index = random.randint(0, sth.tree_size - 1)
leaf_hash = lookup.GetLeafHash(index)
print "index =", index, " hash =", leaf_hash

verifier = merkle.MerkleVerifier()
audit_path = []
for level in range(0, verifier.audit_path_length(index, sth.tree_size)):
    hash = lookup.GetEntry(level, index, sth.tree_size)
    print hash
    audit_path.append(base64.b64decode(hash))

print map(base64.b64encode, audit_path)

assert verifier.verify_leaf_hash_inclusion(base64.b64decode(leaf_hash), index,
                                           audit_path, sth)
