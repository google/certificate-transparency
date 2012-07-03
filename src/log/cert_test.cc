#include <assert.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string>

#include "../util/util.h"
#include "cert.h"

static const char kCertDir[] = "../test/testdata";

// TODO: add test certs with intermediates.
// Valid certificates.
static const char kCACert[] = "ca-cert.pem";
// Issued by ca-cert.pem
static const char kLeafCert[] = "test-cert.pem";
// Issued by ca-cert.pem
static const char kCAProtoCert[] = "ca-protocert.pem";
// Issued by ca-protocert.pem
static const char kProtoCert[] = "test-protocert.pem";

static void CertTest() {
  const std::string cert_dir = std::string(kCertDir);
  std::string leaf_pem, ca_pem, ca_protocert_pem, protocert_pem;
  assert(util::ReadTextFile(cert_dir + "/" + kLeafCert, &leaf_pem));
  assert(util::ReadTextFile(cert_dir + "/" + kCACert, &ca_pem));
  assert(util::ReadTextFile(cert_dir + "/" + kCAProtoCert, &ca_protocert_pem));
  assert(util::ReadTextFile(cert_dir + "/" + kProtoCert, &protocert_pem));

  Cert leaf(leaf_pem);
  assert(leaf.IsLoaded());

  Cert ca(ca_pem);
  assert(ca.IsLoaded());

  Cert ca_proto(ca_protocert_pem);
  assert(ca_proto.IsLoaded());

  Cert proto(protocert_pem);
  assert(proto.IsLoaded());

  // Some facts we know are true about those test certs.
  assert(leaf.HasExtension(NID_authority_key_identifier));
  assert(ca.HasExtension(NID_authority_key_identifier));

  assert(leaf.HasExtension(NID_basic_constraints));
  assert(ca.HasExtension(NID_basic_constraints));

  assert(!leaf.HasBasicConstraintCA());
  assert(ca.HasBasicConstraintCA());
  assert(leaf.IsIssuedBy(ca));
  assert(leaf.IsSignedBy(ca));

  assert(!ca.IsIssuedBy(leaf));
  assert(!ca.IsSignedBy(leaf));

  // Some more extensions.
  assert(ca_proto.HasExtendedKeyUsage(Cert::kCtExtendedKeyUsageOID));
  assert(proto.HasExtension(Cert::kPoisonExtensionOID));
  assert(proto.IsCriticalExtension(Cert::kPoisonExtensionOID));

  // Bogus certs.
  Cert invalid("");
  assert(!invalid.IsLoaded());

  Cert invalid2("-----BEGIN CERTIFICATE-----invalid-----END CERTIFICATE-----");
  assert(!invalid2.IsLoaded());
}

static void CertChainTest() {
  const std::string cert_dir = std::string(kCertDir);
  std::string leaf_pem, ca_pem, ca_protocert_pem, protocert_pem;
  assert(util::ReadTextFile(cert_dir + "/" + kLeafCert, &leaf_pem));
  assert(util::ReadTextFile(cert_dir + "/" + kCACert, &ca_pem));
  assert(util::ReadTextFile(cert_dir + "/" + kCAProtoCert, &ca_protocert_pem));
  assert(util::ReadTextFile(cert_dir + "/" + kProtoCert, &protocert_pem));

  // A single certificate.
  CertChain chain(leaf_pem);
  assert(chain.IsLoaded());

  assert(chain.Length() == 1);
  assert(chain.IsValidIssuerChain());
  assert(chain.IsValidSignatureChain());

  // Add its issuer.
  chain.AddCert(new Cert(ca_pem));
  assert(chain.IsLoaded());
  assert(chain.Length() == 2);
  assert(chain.IsValidIssuerChain());
  assert(chain.IsValidSignatureChain());

  // In reverse order.
  CertChain chain2(ca_pem);
  assert(chain2.IsLoaded());
  assert(chain2.Length() == 1);
  assert(chain2.IsValidIssuerChain());
  assert(chain2.IsValidSignatureChain());

  chain2.AddCert(new Cert(leaf_pem));
  assert(chain2.IsLoaded());
  assert(chain2.Length() == 2);
  assert(!chain2.IsValidIssuerChain());
  assert(!chain2.IsValidSignatureChain());

  // Invalid
  CertChain invalid("");
  assert(!invalid.IsLoaded());

  // A chain with three certificates. Construct from concatenated PEM entries.
  std::string pem_bundle = protocert_pem + ca_protocert_pem + ca_pem;
  CertChain chain3(pem_bundle);
  assert(chain3.IsLoaded());
  assert(chain3.Length() == 3);
  assert(chain3.IsValidIssuerChain());
  assert(chain3.IsValidSignatureChain());

  // A protocert chain.
  pem_bundle = protocert_pem + ca_protocert_pem;
  ProtoCertChain proto_chain(pem_bundle);
  assert(proto_chain.IsLoaded());
  assert(proto_chain.Length() == 2);
  assert(proto_chain.IntermediateLength() == 0);
  assert(proto_chain.IsValidIssuerChain());
  assert(proto_chain.IsValidSignatureChain());
  assert(proto_chain.IsWellFormed());

  // Try to construct a protocert chain from regular certs.
  // The chain should load, but is not well-formed.
  pem_bundle = leaf_pem + ca_pem;
  ProtoCertChain proto_chain2(pem_bundle);
  assert(proto_chain2.IsLoaded());
  assert(proto_chain2.Length() == 2);
  assert(proto_chain2.IntermediateLength() == 0);
  assert(proto_chain2.IsValidIssuerChain());
  assert(proto_chain2.IsValidSignatureChain());
  assert(!proto_chain2.IsWellFormed());
}


int main(int, char**) {
  SSL_library_init();
  printf("Testing certificates\n");
  CertTest();
  printf("Testing certificate chains\n");
  CertChainTest();
  printf("PASS\n");
  return 0;
}
