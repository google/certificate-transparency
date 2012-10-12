/* -*- indent-tabs-mode: nil -*- */
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <openssl/ssl.h>
#include <string>

#include "cert_submission_handler.h"
#include "ct.pb.h"
#include "file_db.h"
#include "frontend.h"
#include "frontend_signer.h"
#include "log_verifier.h"
#include "merkle_verifier.h"
#include "serial_hasher.h"
#include "sqlite_db.h"
#include "test_db.h"
#include "test_signer.h"
#include "util.h"

static const char kCertDir[] = "../test/testdata";

//  Valid certificates.
// Self-signed
static const char kCaCert[] = "ca-cert.pem";
// Issued by ca-cert.pem
static const char kLeafCert[] = "test-cert.pem";
// Issued by ca.pem
static const char kCaPreCert[] = "ca-pre-cert.pem";
// Issued by ca-pre-cert.pem
static const char kPreCert[] = "test-pre-cert.pem";
// The resulting embedded cert, issued by ca-cert.pem
static const char kEmbeddedCert[] = "test-embedded-cert.pem";
// Issued by ca-cert.pem
static const char kIntermediateCert[] = "intermediate-cert.pem";
// Issued by intermediate-cert.pem
static const char kChainLeafCert[] = "test2-cert.pem";

namespace {

using ct::CertificateEntry;
using ct::LoggedCertificate;
using ct::SignedCertificateTimestamp;
using std::string;

// A slightly shorter notation for constructing hex strings from binary blobs.
string H(const string &byte_string) {
  return util::HexString(byte_string);
}

template <class T> class FrontendTest : public ::testing::Test {
 protected:
  FrontendTest()
      : test_db_(),
        test_signer_(),
        verifier_(new LogVerifier(TestSigner::DefaultVerifier(),
                                  new MerkleVerifier(new Sha256Hasher()))),
        checker_(),
        frontend_(new Frontend(new CertSubmissionHandler(&checker_),
                               new FrontendSigner(
                                   db(), TestSigner::DefaultSigner()))) {}

  void SetUp() {
    cert_dir_ = string(kCertDir);
    ASSERT_TRUE(util::ReadTextFile(cert_dir_ + "/" + kLeafCert, &leaf_pem_));
    ASSERT_TRUE(util::ReadTextFile(cert_dir_ + "/" + kCaPreCert,
                                   &ca_precert_pem_));
    ASSERT_TRUE(util::ReadTextFile(cert_dir_ + "/" + kPreCert,
                                   &precert_pem_));
    ASSERT_TRUE(util::ReadTextFile(cert_dir_ + "/" + kIntermediateCert,
                                   &intermediate_pem_));
    ASSERT_TRUE(util::ReadTextFile(cert_dir_ + "/" + kChainLeafCert,
                                   &chain_leaf_pem_));
    ASSERT_TRUE(util::ReadTextFile(cert_dir_ + "/" + kCaCert, &ca_pem_));
    ASSERT_TRUE(util::ReadTextFile(cert_dir_ + "/" + kEmbeddedCert,
                                   &embedded_pem_));
    ASSERT_TRUE(checker_.LoadTrustedCertificate(cert_dir_ + "/" + kCaCert));
  }

  ~FrontendTest() {
    delete verifier_;
    delete frontend_;
  }

  T *db() const { return test_db_.db(); }

  TestDB<T> test_db_;
  TestSigner test_signer_;
  LogVerifier *verifier_;
  CertChecker checker_;
  Frontend *frontend_;
  string cert_dir_;
  string leaf_pem_;
  string ca_precert_pem_;
  string precert_pem_;
  string intermediate_pem_;
  string chain_leaf_pem_;
  string embedded_pem_;
  string ca_pem_;
};

typedef testing::Types<FileDB, SQLiteDB> Databases;

TYPED_TEST_CASE(FrontendTest, Databases);

TYPED_TEST(FrontendTest, TestSubmitValid) {
  SignedCertificateTimestamp sct;
  EXPECT_EQ(Frontend::NEW,
            this->frontend_->QueueEntry(CertificateEntry::X509_ENTRY,
                                        this->leaf_pem_, &sct));

  // Look it up and expect to get the right thing back.
  LoggedCertificate logged_cert;
  Cert cert(this->leaf_pem_);
  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupCertificateByHash(cert.Sha256Digest(),
                                                &logged_cert));

  // Compare the leaf cert.
  string der_string = cert.DerEncoding();
  EXPECT_EQ(H(der_string),
            H(logged_cert.sct().entry().leaf_certificate()));

  // And verify the signature.
  sct.mutable_entry()->set_leaf_certificate(der_string);
  EXPECT_EQ(LogVerifier::VERIFY_OK,
            this->verifier_->VerifySignedCertificateTimestamp(sct));
}

TYPED_TEST(FrontendTest, TestSubmitValidWithIntermediate) {
  SignedCertificateTimestamp sct;
  string submission = this->chain_leaf_pem_ + this->intermediate_pem_;
  EXPECT_EQ(Frontend::NEW,
            this->frontend_->QueueEntry(CertificateEntry::X509_ENTRY,
                                        submission, &sct));

  // Look it up and expect to get the right thing back.
  LoggedCertificate logged_cert;
  Cert cert(this->chain_leaf_pem_);
  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupCertificateByHash(cert.Sha256Digest(),
                                                &logged_cert));

  // Compare the leaf cert.
  string der_string = cert.DerEncoding();
  EXPECT_EQ(H(der_string),
            H(logged_cert.sct().entry().leaf_certificate()));

  // And verify the signature.
  sct.mutable_entry()->set_leaf_certificate(der_string);
  EXPECT_EQ(LogVerifier::VERIFY_OK,
            this->verifier_->VerifySignedCertificateTimestamp(sct));

  // Compare the first intermediate.
  ASSERT_GE(logged_cert.sct().entry().intermediates_size(), 1);
  Cert cert2(this->intermediate_pem_);
  EXPECT_EQ(H(cert2.DerEncoding()),
            H(logged_cert.sct().entry().intermediates(0)));
}

TYPED_TEST(FrontendTest, TestSubmitDuplicate) {
  SignedCertificateTimestamp sct;
  EXPECT_EQ(Frontend::NEW,
            this->frontend_->QueueEntry(CertificateEntry::X509_ENTRY,
                                        this->leaf_pem_, NULL));
  EXPECT_EQ(Frontend::DUPLICATE,
            this->frontend_->QueueEntry(CertificateEntry::X509_ENTRY,
                                        this->leaf_pem_, &sct));

  // Look it up and expect to get the right thing back.
  LoggedCertificate logged_cert;
  Cert cert(this->leaf_pem_);
  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupCertificateByHash(cert.Sha256Digest(),
                                                &logged_cert));

  // Compare the leaf cert.
  string der_string = cert.DerEncoding();
  EXPECT_EQ(H(der_string),
            H(logged_cert.sct().entry().leaf_certificate()));

  // And verify the signature.
  sct.mutable_entry()->set_leaf_certificate(der_string);
  EXPECT_EQ(LogVerifier::VERIFY_OK,
            this->verifier_->VerifySignedCertificateTimestamp(sct));
}

TYPED_TEST(FrontendTest, TestSubmitInvalidChain) {
  SignedCertificateTimestamp sct;
  // Missing intermediate.
  EXPECT_EQ(Frontend::CERTIFICATE_VERIFY_ERROR,
            this->frontend_->QueueEntry(CertificateEntry::X509_ENTRY,
                                        this->chain_leaf_pem_, &sct));
  EXPECT_FALSE(sct.has_signature());
}

TYPED_TEST(FrontendTest, TestSubmitInvalidPem) {
  SignedCertificateTimestamp sct;
  string fake_cert("-----BEGIN CERTIFICATE-----\n"
                   "Iamnotavalidcert\n"
                   "-----END CERTIFICATE-----\n");
  EXPECT_EQ(Frontend::BAD_PEM_FORMAT,
            this->frontend_->QueueEntry(CertificateEntry::X509_ENTRY,
                                        fake_cert, &sct));
  EXPECT_FALSE(sct.has_signature());
}

TYPED_TEST(FrontendTest, TestSubmitPrecert) {
  SignedCertificateTimestamp sct;
  string submission = this->precert_pem_ + this->ca_precert_pem_;
  EXPECT_EQ(Frontend::NEW,
            this->frontend_->QueueEntry(CertificateEntry::PRECERT_ENTRY,
                                        submission, &sct));

  CertChain chain(this->embedded_pem_);
  CertificateEntry entry;
  CHECK_EQ(CertSubmissionHandler::OK,
           CertSubmissionHandler::X509ChainToEntry(chain, &entry));

  // Look it up.
  string hash = Sha256Hasher::Sha256Digest(entry.leaf_certificate());
  LoggedCertificate logged_cert;
  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupCertificateByHash(hash, &logged_cert));
  Cert pre(this->precert_pem_);
  Cert ca_pre(this->ca_precert_pem_);

  // Verify the signature.
  sct.mutable_entry()->set_leaf_certificate(entry.leaf_certificate());
  EXPECT_EQ(LogVerifier::VERIFY_OK,
            this->verifier_->VerifySignedCertificateTimestamp(sct));

  // Expect to have the original certs logged in the chain.
  ASSERT_GE(logged_cert.sct().entry().intermediates_size(), 2);
  EXPECT_EQ(H(pre.DerEncoding()),
            H(logged_cert.sct().entry().intermediates(0)));
  EXPECT_EQ(H(ca_pre.DerEncoding()),
            H(logged_cert.sct().entry().intermediates(1)));
}

}  // namespace

int main(int argc, char **argv) {
  // Change the defaults. Can be overridden on command line.
  // Log to stderr instead of log files.
  FLAGS_logtostderr = true;
  // Only log fatal messages by default.
  FLAGS_minloglevel = 3;
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  ::testing::InitGoogleTest(&argc, argv);
  SSL_library_init();
  return RUN_ALL_TESTS();
}
