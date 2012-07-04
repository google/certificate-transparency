#include <assert.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string>

#include "../util/util.h"
#include "cert.h"
#include "cert_checker.h"

static const char kCertDir[] = "../test/testdata";

// Valid certificates.
// Self-signed
static const char kCaCert[] = "ca-cert.pem";
// Issued by ca-cert.pem
static const char kLeafCert[] = "test-cert.pem";
// Issued by ca-cert.pem
static const char kCaProtoCert[] = "ca-proto-cert.pem";
// Issued by ca-proto-cert.pem
static const char kProtoCert[] = "test-proto-cert.pem";
// Issued by ca-cert.pem
static const char kIntermediateCert[] = "intermediate-cert.pem";
// Issued by intermediate-cert.pem
static const char kChainLeafCert[] = "test2-cert.pem";

static void CertCheckTest() {
  CertChecker checker;
  const std::string cert_dir = std::string(kCertDir);
  std::string leaf_pem, ca_pem, chain_leaf_pem, intermediate_pem;
  assert(util::ReadTextFile(cert_dir + "/" + kLeafCert, &leaf_pem));
  assert(util::ReadTextFile(cert_dir + "/" + kCaCert, &ca_pem));
  assert(util::ReadTextFile(cert_dir + "/" + kChainLeafCert, &chain_leaf_pem));
  assert(util::ReadTextFile(cert_dir + "/" + kIntermediateCert,
                            &intermediate_pem));
  CertChain chain(leaf_pem);
  assert(chain.IsLoaded());

  // Fail as we have no CA certs.
  assert(!checker.CheckCertChain(chain));

  // Load CA certs and expect success.
  assert(checker.LoadTrustedCertificate(cert_dir + "/" + kCaCert));
  assert(checker.CheckCertChain(chain));

  // A second chain with an intermediate.
  CertChain chain2(chain_leaf_pem);
  assert(chain2.IsLoaded());
  // Fail as it doesn't chain to a trusted CA.
  assert(!checker.CheckCertChain(chain2));
  // Add the intermediate and expect success.
  chain2.AddCert(new Cert(intermediate_pem));
  assert(checker.CheckCertChain(chain2));

  // An invalid chain, with two certs in wrong order.
  CertChain invalid(intermediate_pem + chain_leaf_pem);
  assert(invalid.IsLoaded());
  assert(!checker.CheckCertChain(invalid));
}

static void ProtoCertCheckTest() {
  CertChecker checker;
  const std::string cert_dir = std::string(kCertDir);

  std::string protocert_pem, ca_protocert_pem;
  assert(util::ReadTextFile(cert_dir + "/" + kProtoCert, &protocert_pem));
  assert(util::ReadTextFile(cert_dir + "/" + kCaProtoCert, &ca_protocert_pem));
  const std::string chain_pem = protocert_pem + ca_protocert_pem;
  ProtoCertChain chain(chain_pem);

  assert(chain.IsLoaded());
  assert(chain.IsWellFormed());

  // Fail as we have no CA certs.
  assert(!checker.CheckProtoCertChain(chain));

  // Load CA certs and expect success.
  checker.LoadTrustedCertificate(cert_dir + "/" + kCaCert);
  assert(checker.CheckProtoCertChain(chain));

  // A second, invalid chain, with no CA protocert.
  ProtoCertChain chain2(protocert_pem);
  assert(chain2.IsLoaded());
  assert (!chain2.IsWellFormed());
  assert(!checker.CheckProtoCertChain(chain2));
}

int main(int, char**) {
  SSL_library_init();
  printf("Testing certificate verification\n");
  CertCheckTest();
  printf("Testing proto-certificate verification\n");
  ProtoCertCheckTest();
  printf("PASS\n");
  return 0;
}
