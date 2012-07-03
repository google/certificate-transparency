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
// Issued by ca.pem
static const char kLeafCert[] = "test-cert.pem";
// Issued by ca.pem
static const char kCaProtoCert[] = "ca-protocert.pem";
// Issued by ca-protocert.pem
static const char kProtoCert[] = "test-protocert.pem";

static void CertCheckTest() {
  CertChecker checker;
  const std::string cert_dir = std::string(kCertDir);
  std::string leaf_pem, ca_pem;
  assert(util::ReadTextFile(cert_dir + "/" + kLeafCert, &leaf_pem));
  assert(util::ReadTextFile(cert_dir + "/" + kCaCert, &ca_pem));
  CertChain chain(leaf_pem);
  assert(chain.IsLoaded());

  // Fail as we have no CA certs.
  assert(!checker.CheckCertChain(chain));

  // Load CA certs and expect success.
  assert(checker.LoadTrustedCertificate(cert_dir + "/" + kCaCert));
  assert(checker.CheckCertChain(chain));

  // A second, invalid chain, with two certs in wrong order.
  CertChain chain2(ca_pem + leaf_pem);
  assert(chain2.IsLoaded());
  assert(!checker.CheckCertChain(chain2));
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
