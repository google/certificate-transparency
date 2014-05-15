import dns.resolver
import dns.rdatatype
import random
import shlex
import subprocess

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
        return self.GetOne('sth.example.com')

    def GetTreeSize(self):
        sth = self.GetSTH()
        return int(str(sth).split('.')[0])

    def GetEntry(self, level, index, size):
        return self.GetOne(str(level) + '.' + str(index) + '.' + str(size)
                           + '.tree.example.com')

    def GetLeafHash(self, index):
        return self.GetOne(str(index) + '.leafhash.example.com')

class DNSServerRunner:
    def Run(self, cmd):
        args = shlex.split(cmd)
        self.proc = subprocess.Popen(args)

server_cmd = "./ct-dns-server --port=1111 --domain=example.com. --db=/tmp/ct"
runner = DNSServerRunner()
runner.Run(server_cmd)

lookup = CTDNSLookup(['127.0.0.1'], 1111)
print "sth =", lookup.GetSTH()
size = lookup.GetTreeSize()
print "size =", lookup.GetTreeSize()

# Verify a random entry
index = random.randint(0, size - 1)
running_hash = lookup.GetLeafHash(index)
print "index =", index, " hash =", running_hash
for level in range(0, 100):
    print lookup.GetEntry(level, index, size)

#resolver = dns.resolver.Resolver(configure=False)
#resolver.nameservers = ['213.129.69.153']
#resolver.port = 5353
#answers = resolver.query('google-public-dns-a.google.com', 'TXT')

#resolver.nameservers = ['127.0.0.1']
#resolver.port = 1111

#answers = resolver.query('sth.example.com', 'TXT')

#for a in answers:
#    print a
