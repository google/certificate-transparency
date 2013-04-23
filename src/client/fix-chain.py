#!/usr/bin/env python

# Given a certificate chain that the log won't accept, try to fix it up
# into one that will be accepted.

# Based on pyasn1 example code.

from base64 import b64encode
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, univ
from pyasn1_modules import pem, rfc2459
import sys
from urllib2 import urlopen

if len(sys.argv) != 1:
  print """Usage:
  $ %s < somecertificates.pem""" % sys.argv[0]
  sys.exit(-1)

cStart = '-----BEGIN CERTIFICATE-----'
cEnd = '-----END CERTIFICATE-----'

certType = rfc2459.Certificate()

# RFC 2459 is not sufficient for X509v3 certificates, extra stuff here.
# RFC 5280 4.2.2.1

id_pe_authorityInfoAccess = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.1')

class AccessDescription(univ.Sequence):
  """
     AccessDescription  ::=  SEQUENCE {
                accessMethod          OBJECT IDENTIFIER,
                accessLocation        GeneralName  }
  """
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
    namedtype.NamedType('accessLocation', rfc2459.GeneralName()))

class AuthorityInfoAccessSyntax(univ.SequenceOf):
  """
  AuthorityInfoAccessSyntax  ::=
             SEQUENCE SIZE (1..MAX) OF AccessDescription
  """
  # FIXME: SIZE not encoded.
  componentType = AccessDescription()

id_ad_caIssuers = univ.ObjectIdentifier('1.3.6.1.5.5.7.48.2')

# End of RFC 5280 4.2.2.1

def getIssuerFromAIA(cert):
  tbs = cert.getComponentByName('tbsCertificate')
  extensions = tbs.getComponentByName('extensions') or []

  for extension in extensions:
    oid = extension.getComponentByName('extnID')
    if oid != id_pe_authorityInfoAccess:
      continue
    
    print extension.prettyPrint()

    value, rest = decoder.decode(extension.getComponentByName('extnValue'),
                                 asn1Spec=univ.OctetString())
    assert rest == ""
    aia, rest = decoder.decode(value, asn1Spec=AuthorityInfoAccessSyntax())
    assert rest == ""

    print aia.prettyPrint()

    for ad in aia:
      oid = ad.getComponentByName('accessMethod')
      if oid != id_ad_caIssuers:
        continue
      
      print ad.prettyPrint()

      loc = ad.getComponentByName('accessLocation').\
        getComponentByName('uniformResourceIdentifier')
      print type(loc), loc

      certHandle = urlopen(str(loc))
      return certHandle.read()

# Note that this is a non-standard encoding of the DN, but unlike the
# standard encoding it captures nesting information. That is,
# attributes that are within a single RelativeDistinguishedName are
# surrounded by [].
def DNToString(dn):
  rdns = dn.getComponent()
  ret = ''
  for rdn in rdns:
    ret += '['
    
    for attr in rdn:
      attrType = attr.getComponentByName('type')

      if attrType == rfc2459.emailAddress:
        val, rest = decoder.decode(attr.getComponentByName('value'),
                                   asn1Spec=rfc2459.Pkcs9email())
        assert rest == ""

        # Strictly speaking, this is IA5, not ASCII.
        val = str(val).decode('ascii')
      else:
        val, rest = decoder.decode(attr.getComponentByName('value'),
                                   asn1Spec=rfc2459.X520name())
        assert rest == ""
      
        valt = val.getName()
        val = val.getComponent()
      
        if valt == 'printableString':
          val = str(val)
        elif valt == 'teletexString':
          # Strictly this is a T.61 string. T.61 no longer exists as a
          # standard and some certs mark ISO 8859-1 as
          # teletexString. And we should never see this, but we do.
          val = str(val).decode('iso8859-1')
        else:
          print valt
          assert False
        
      assert val is not None
      
      ret += '/' + str(attrType) + '=' + val
      
    ret += ']'
    
  return ret

certs = {}
inChain = []

while 1:
  idx, substrate = pem.readPemBlocksFromFile(sys.stdin, (cStart, cEnd))
  if not substrate:
    break

  cert, rest = decoder.decode(substrate, asn1Spec=certType)
  assert rest == ""

  tbs = cert.getComponentByName('tbsCertificate')

  subjectDN = tbs.getComponentByName('subject')
  print DNToString(subjectDN)

  certs[DNToString(subjectDN)] = cert
  inChain.append(cert)

#for subject, cert in certs.iteritems():
#  print subject

# Assume the first cert in the chain is the final cert
outChain = [inChain[0]]

while True:
  assert len(outChain) < 100
  
  cert = outChain[-1]

  tbs = cert.getComponentByName('tbsCertificate')

  subjectDN = tbs.getComponentByName('subject')
  print 'subject:', DNToString(subjectDN)

  issuerDN = tbs.getComponentByName('issuer')
  #print issuerDN.prettyPrint()
  issuerDNstr = DNToString(issuerDN)
  print 'issuer:', issuerDNstr

  print

  if issuerDN == subjectDN:
    break

  if issuerDNstr in certs:
    issuer = certs[issuerDNstr]
  else:
    issuer = getIssuerFromAIA(cert)
    if issuer is None:
      print "Can't get issuer, giving up"
      break

  assert issuer is not None

  outChain.append(issuer)

for cert in outChain:
    print cStart
    b64 = b64encode(encoder.encode(cert))
    for n in range(0, len(b64), 64):
      print b64[n:n+64]
    print cEnd

print('*** %d PEM cert(s) deserialized, fixed chain is %d long' % (
  len(inChain),
  len(outChain)))
