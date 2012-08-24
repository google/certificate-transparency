#include <gtest/gtest.h>
#include <openssl/ssl.h>
#include <string>

#include "cert_checker.h"
#include "cert_submission_handler.h"
#include "ct.pb.h"
#include "types.h"
#include "util.h"

static const char kCertDir[] = "../test/testdata";

// Valid certificates.
// Self-signed
static const char kCaCert[] = "ca-cert.pem";
// Issued by ca.pem
static const char kLeafCert[] = "test-cert.pem";
// Issued by ca.pem
static const char kCaPreCert[] = "ca-proto-cert.pem";
// Issued by ca-precert.pem
static const char kPreCert[] = "test-proto-cert.pem";
// Issued by ca-cert.pem
static const char kIntermediateCert[] = "intermediate-cert.pem";
// Issued by intermediate-cert.pem
static const char kChainLeafCert[] = "test2-cert.pem";

namespace {

class CertSubmissionHandlerTest : public ::testing::Test {
 protected:
  bstring ca_;
  bstring leaf_;
  bstring ca_precert_;
  bstring precert_;
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
    ASSERT_TRUE(util::ReadBinaryFile(cert_dir_ + "/" + kCaPreCert,
                                     &ca_precert_));
    ASSERT_TRUE(util::ReadBinaryFile(cert_dir_ + "/" + kPreCert,
                                     &precert_));
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
  CertificateEntry *entry =
      handler_->ProcessSubmission(CertificateEntry::X509_ENTRY, leaf_);
  ASSERT_TRUE(entry != NULL);
  // TODO: further checks.
  delete entry;

  // Submit a leaf cert with a missing intermediate.
  entry = handler_->ProcessSubmission(CertificateEntry::X509_ENTRY, chain_leaf_);
  EXPECT_EQ(NULL, entry);

  // Submit a chain.
  bstring submit = chain_leaf_ + intermediate_;
  entry = handler_->ProcessSubmission(CertificateEntry::X509_ENTRY, submit);
  ASSERT_TRUE(entry != NULL);
  delete entry;

  // An invalid chain with two certs in wrong order.
  bstring invalid_submit = ca_;
  invalid_submit.append(leaf_);
  entry = handler_->ProcessSubmission(CertificateEntry::X509_ENTRY,
                                      invalid_submit);
  EXPECT_EQ(NULL, entry);
}

TEST_F(CertSubmissionHandlerTest, SubmitPreCertChain) {
  bstring submit = precert_ + ca_precert_;

  CertificateEntry *entry =
      handler_->ProcessSubmission(CertificateEntry::PRECERT_ENTRY, submit);
  ASSERT_TRUE(entry != NULL);
  delete entry;

  // In wrong order.
  submit = ca_precert_ + precert_;
  entry = handler_->ProcessSubmission(CertificateEntry::PRECERT_ENTRY, submit);
  EXPECT_EQ(NULL, entry);
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  SSL_library_init();
  return RUN_ALL_TESTS();
}
