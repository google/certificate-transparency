#include <gtest/gtest.h>
#include <openssl/ssl.h>
#include <string>

#include "cert_checker.h"
#include "cert_submission_handler.h"
#include "ct.pb.h"
#include "util.h"

static const char kCertDir[] = "../test/testdata";

// Valid certificates.
// Self-signed
static const char kCaCert[] = "ca-cert.pem";
// Issued by ca.pem
static const char kLeafCert[] = "test-cert.pem";
// Issued by ca.pem
static const char kCaPreCert[] = "ca-pre-cert.pem";
// Issued by ca-pre-cert.pem
static const char kPreCert[] = "test-pre-cert.pem";
// Issued by ca-cert.pem
static const char kIntermediateCert[] = "intermediate-cert.pem";
// Issued by intermediate-cert.pem
static const char kChainLeafCert[] = "test2-cert.pem";

namespace {

using ct::CertificateEntry;
using std::string;

class CertSubmissionHandlerTest : public ::testing::Test {
 protected:
  string ca_;
  string leaf_;
  string ca_precert_;
  string precert_;
  string intermediate_;
  string chain_leaf_;
  string cert_dir_;
  CertSubmissionHandler *handler_;
  CertChecker *checker_;

  CertSubmissionHandlerTest() : handler_(NULL) {}

  void SetUp() {
    cert_dir_ = string(kCertDir);
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

TEST_F(CertSubmissionHandlerTest, SubmitCert) {
  CertificateEntry entry;
  entry.set_type(CertificateEntry::X509_ENTRY);
  // Submit a leaf cert.
  EXPECT_EQ(SubmissionHandler::OK, handler_->ProcessSubmission(leaf_, &entry));
  EXPECT_TRUE(entry.has_leaf_certificate());
  EXPECT_EQ(0, entry.intermediates_size());
}

TEST_F(CertSubmissionHandlerTest, SubmitEmptyCert) {
  CertificateEntry entry;
  entry.set_type(CertificateEntry::X509_ENTRY);
  EXPECT_EQ(SubmissionHandler::EMPTY_SUBMISSION,
            handler_->ProcessSubmission("", &entry));
}

TEST_F(CertSubmissionHandlerTest, SubmitInvalidCert) {
  CertificateEntry entry;
  entry.set_type(CertificateEntry::X509_ENTRY);
  EXPECT_EQ(SubmissionHandler::INVALID_PEM_ENCODED_CHAIN,
            handler_->ProcessSubmission("-----BEGIN CERTIFICATE-----\ninvalid"
                                        "\n-----END CERTIFICATE-----", &entry));
}

TEST_F(CertSubmissionHandlerTest, SubmitChain) {
  // Submit a chain.
  string submit = chain_leaf_ + intermediate_;
  CertificateEntry entry;
  entry.set_type(CertificateEntry::X509_ENTRY);
  EXPECT_EQ(SubmissionHandler::OK, handler_->ProcessSubmission(submit, &entry));
  EXPECT_TRUE(entry.has_leaf_certificate());
  EXPECT_EQ(1, entry.intermediates_size());
}

TEST_F(CertSubmissionHandlerTest, SubmitPartialChain) {
  CertificateEntry entry;
  entry.set_type(CertificateEntry::X509_ENTRY);
  // Submit a leaf cert with a missing intermediate.
  EXPECT_EQ(SubmissionHandler::UNKNOWN_ROOT,
            handler_->ProcessSubmission(chain_leaf_, &entry));
}

TEST_F(CertSubmissionHandlerTest, SubmitInvalidChain) {
  string invalid_submit = ca_;
  invalid_submit.append(leaf_);
  CertificateEntry entry;
  entry.set_type(CertificateEntry::X509_ENTRY);
  // An invalid chain with two certs in wrong order.
  EXPECT_EQ(SubmissionHandler::INVALID_CERTIFICATE_CHAIN,
            handler_->ProcessSubmission(invalid_submit, &entry));
}

TEST_F(CertSubmissionHandlerTest, SubmitCertAsPreCert) {
  CertificateEntry entry;
  entry.set_type(CertificateEntry::PRECERT_ENTRY);
  // Various things are wrong here, so do not expect a specific error.
  EXPECT_NE(SubmissionHandler::OK, handler_->ProcessSubmission(leaf_, &entry));
}

TEST_F(CertSubmissionHandlerTest, SubmitCertChainAsPreCert) {
  string submit = chain_leaf_ + intermediate_;
  CertificateEntry entry;
  entry.set_type(CertificateEntry::PRECERT_ENTRY);
  EXPECT_NE(SubmissionHandler::OK, handler_->ProcessSubmission(submit, &entry));
}

TEST_F(CertSubmissionHandlerTest, SubmitPreCertChain) {
  string submit = precert_ + ca_precert_;
  CertificateEntry entry;
  entry.set_type(CertificateEntry::PRECERT_ENTRY);
  EXPECT_EQ(SubmissionHandler::OK, handler_->ProcessSubmission(submit, &entry));
  EXPECT_TRUE(entry.has_leaf_certificate());
  // |intermediates| is the entire precert chain (excluding root).
  EXPECT_EQ(2, entry.intermediates_size());
}

TEST_F(CertSubmissionHandlerTest, SubmitInvalidPreCertChain) {
  // In wrong order.
  string submit = ca_precert_ + precert_;
  CertificateEntry entry;
  entry.set_type(CertificateEntry::PRECERT_ENTRY);
  EXPECT_NE(SubmissionHandler::OK, handler_->ProcessSubmission(submit, &entry));
}

TEST_F(CertSubmissionHandlerTest, SubmitPreCertChainAsCertChain) {
  string submit = precert_ + ca_precert_;
  CertificateEntry entry;
  entry.set_type(CertificateEntry::X509_ENTRY);
  // This should fail since ca_precert_ is not a CA cert (CA:false).
  EXPECT_NE(SubmissionHandler::OK, handler_->ProcessSubmission(submit, &entry));
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  SSL_library_init();
  return RUN_ALL_TESTS();
}
