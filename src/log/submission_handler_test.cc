#include <assert.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string>

#include "../util/util.h"
#include "cert_checker.h"
#include "cert_submission_handler.h"
#include "log_entry.h"

static const char kCertDir[] = "../test/testdata";

// Valid certificates.
// Self-signed
static const char kCaCert[] = "ca-cert.pem";
// Issued by ca.pem
static const char kLeafCert[] = "test-cert.pem";
// Issued by ca.pem
static const char kCaProtoCert[] = "ca-proto-cert.pem";
// Issued by ca-protocert.pem
static const char kProtoCert[] = "test-proto-cert.pem";
// Issued by ca-cert.pem
static const char kIntermediateCert[] = "intermediate-cert.pem";
// Issued by intermediate-cert.pem
static const char kChainLeafCert[] = "test2-cert.pem";

static void CertChainSubmitTest() {
  CertChecker checker;
  const std::string cert_dir = std::string(kCertDir);
  checker.LoadTrustedCertificate(cert_dir + "/" + kCaCert);
  CertSubmissionHandler handler(&checker);

  // Submit a leaf cert.
  bstring leaf;
  assert(util::ReadBinaryFile(cert_dir + "/" + kLeafCert, &leaf));
  LogEntry *entry = handler.ProcessSubmission(LogEntry::X509_CHAIN_ENTRY, leaf);
  assert(entry != NULL);
  // TODO: further checks.
  delete entry;

  // Submit a leaf cert with a missing intermediate.
  bstring chain_leaf;
  assert(util::ReadBinaryFile(cert_dir + "/" + kChainLeafCert, &chain_leaf));
  entry = handler.ProcessSubmission(LogEntry::X509_CHAIN_ENTRY, chain_leaf);
  assert(entry == NULL);

  // Submit a chain.
  bstring intermediate;
  assert(util::ReadBinaryFile(cert_dir + "/" + kIntermediateCert,
                            &intermediate));
  bstring submit = chain_leaf + intermediate;
  entry = handler.ProcessSubmission(LogEntry::X509_CHAIN_ENTRY, submit);
  assert(entry != NULL);
  delete entry;

  // An invalid chain with two certs in wrong order.
  bstring invalid_submit;
  assert(util::ReadBinaryFile(cert_dir + "/" + kCaCert, &invalid_submit));
  invalid_submit.append(leaf);
  entry = handler.ProcessSubmission(LogEntry::X509_CHAIN_ENTRY, invalid_submit);
  assert(entry == NULL);
}

static void ProtoCertChainSubmitTest() {
  CertChecker checker;
  const std::string cert_dir = std::string(kCertDir);
  checker.LoadTrustedCertificate(cert_dir + "/" + kCaCert);
  CertSubmissionHandler handler(&checker);

  bstring proto;
  assert(util::ReadBinaryFile(cert_dir + "/" + kProtoCert, &proto));
  bstring ca_proto;
  assert(util::ReadBinaryFile(cert_dir + "/" + kCaProtoCert, &ca_proto));
  bstring submit = proto + ca_proto;

  LogEntry *entry = handler.ProcessSubmission(LogEntry::PROTOCERT_CHAIN_ENTRY,
                                              submit);
  assert(entry != NULL);
  delete entry;

  // In wrong order.
  submit = ca_proto + proto;
  entry = handler.ProcessSubmission(LogEntry::PROTOCERT_CHAIN_ENTRY, submit);
  assert(entry == NULL);
}

int main(int, char**) {
  SSL_library_init();
  printf("Testing certificate verification\n");
  CertChainSubmitTest();
  printf("Testing proto-certificate verification\n");
  ProtoCertChainSubmitTest();
  printf("PASS\n");
  return 0;
}
