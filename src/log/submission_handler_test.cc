#include <gtest/gtest.h>
#include <openssl/ssl.h>
#include <string>

#include "../include/types.h"
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

namespace {

class CertSubmissionHandlerTest : public ::testing::Test {
 protected:
  bstring ca_;
  bstring leaf_;
  bstring ca_protocert_;
  bstring protocert_;
  bstring intermediate_;
  bstring chain_leaf_;
  std::string cert_dir_;
  CertSubmissionHandler *handler_;
  CertChecker *checker_;

  CertSubmissionHandlerTest() : handler_(NULL) {}

  void SetUp() {
    cert_dir_ = std::string(kCertDir);
    checker_ = new CertChecker();
    checker_->LoadTrustedCertificate(cert_dir_ + "/" + kCaCert);
    handler_ = new CertSubmissionHandler(checker_);
    ASSERT_TRUE(util::ReadBinaryFile(cert_dir_ + "/" + kCaCert, &ca_));
    ASSERT_TRUE(util::ReadBinaryFile(cert_dir_ + "/" + kLeafCert, &leaf_));
    ASSERT_TRUE(util::ReadBinaryFile(cert_dir_ + "/" + kCaProtoCert,
                                     &ca_protocert_));
    ASSERT_TRUE(util::ReadBinaryFile(cert_dir_ + "/" + kProtoCert,
                                     &protocert_));
    ASSERT_TRUE(util::ReadBinaryFile(cert_dir_ + "/" + kIntermediateCert,
                                     &intermediate_));
    ASSERT_TRUE(util::ReadBinaryFile(cert_dir_ + "/" + kChainLeafCert,
                                     &chain_leaf_));
  }

  ~CertSubmissionHandlerTest() {
    delete checker_;
    delete handler_;
  }
};

TEST_F(CertSubmissionHandlerTest, SubmitCertChain) {
  // Submit a leaf cert.
  LogEntry *entry = handler_->ProcessSubmission(LogEntry::X509_CHAIN_ENTRY,
                                                leaf_);
  ASSERT_TRUE(entry != NULL);
  // TODO: further checks.
  delete entry;

  // Submit a leaf cert with a missing intermediate.
  entry = handler_->ProcessSubmission(LogEntry::X509_CHAIN_ENTRY, chain_leaf_);
  EXPECT_EQ(NULL, entry);

  // Submit a chain.
  bstring submit = chain_leaf_ + intermediate_;
  entry = handler_->ProcessSubmission(LogEntry::X509_CHAIN_ENTRY, submit);
  ASSERT_TRUE(entry != NULL);
  delete entry;

  // An invalid chain with two certs in wrong order.
  bstring invalid_submit = ca_;
  invalid_submit.append(leaf_);
  entry = handler_->ProcessSubmission(LogEntry::X509_CHAIN_ENTRY,
                                      invalid_submit);
  EXPECT_EQ(NULL, entry);
}

TEST_F(CertSubmissionHandlerTest, SubmitProtoCertChain) {
  bstring submit = protocert_ + ca_protocert_;

  LogEntry *entry = handler_->ProcessSubmission(LogEntry::PROTOCERT_CHAIN_ENTRY,
                                                submit);
  ASSERT_TRUE(entry != NULL);
  delete entry;

  // In wrong order.
  submit = ca_protocert_ + protocert_;
  entry = handler_->ProcessSubmission(LogEntry::PROTOCERT_CHAIN_ENTRY, submit);
  EXPECT_EQ(NULL, entry);
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  SSL_library_init();
  return RUN_ALL_TESTS();
}
