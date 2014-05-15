import dns.resolver
import dns.rdatatype

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
        return str(sth).split('.')[0]

lookup = CTDNSLookup(['127.0.0.1'], 1111)
print "sth =", lookup.GetSTH()
print "size =", lookup.GetTreeSize()

#resolver = dns.resolver.Resolver(configure=False)
#resolver.nameservers = ['213.129.69.153']
#resolver.port = 5353
#answers = resolver.query('google-public-dns-a.google.com', 'TXT')

#resolver.nameservers = ['127.0.0.1']
#resolver.port = 1111

#answers = resolver.query('sth.example.com', 'TXT')

#for a in answers:
#    print a
