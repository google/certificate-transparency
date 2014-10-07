/* -*- indent-tabs-mode: nil -*- */
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>

#include "log/cert_submission_handler.h"
#include "log/ct_extensions.h"
#include "log/file_db.h"
#include "log/frontend.h"
#include "log/frontend_signer.h"
#include "log/log_verifier.h"
#include "log/logged_certificate.h"
#include "log/sqlite_db.h"
#include "log/test_db.h"
#include "log/test_signer.h"
#include "merkletree/merkle_verifier.h"
#include "merkletree/serial_hasher.h"
#include "proto/ct.pb.h"
#include "util/testing.h"
#include "util/util.h"

DEFINE_string(test_certs_dir, "../test/testdata", "Path to test certificates");

//  Valid certificates.
// Self-signed
static const char kCaCert[] = "ca-cert.pem";
// Issued by ca-cert.pem
static const char kLeafCert[] = "test-cert.pem";
// Issued by ca.pem
static const char kCaPreCert[] = "ca-pre-cert.pem";
// Issued by ca-cert.pem
static const char kPreCert[] = "test-embedded-pre-cert.pem";
// Issued by ca-pre-cert.pem
static const char kPreWithPreCaCert[] = "test-embedded-with-preca-pre-cert.pem";
// The resulting embedded certs, issued by ca-cert.pem
static const char kEmbeddedCert[] = "test-embedded-cert.pem";
static const char kEmbeddedWithPreCaCert[] =
    "test-embedded-with-preca-cert.pem";
// Issued by ca-cert.pem
static const char kIntermediateCert[] = "intermediate-cert.pem";
// Issued by intermediate-cert.pem
static const char kChainLeafCert[] = "test-intermediate-cert.pem";

namespace {

using cert_trans::Cert;
using cert_trans::CertChain;
using cert_trans::CertChecker;
using cert_trans::LoggedCertificate;
using cert_trans::PreCertChain;
using ct::LogEntry;
using ct::SignedCertificateTimestamp;
using std::string;

typedef Database<LoggedCertificate> DB;
typedef Frontend FE;

// A slightly shorter notation for constructing hex strings from binary blobs.
string H(const string &byte_string) {
  return util::HexString(byte_string);
}

template <class T> class FrontendTest : public ::testing::Test {
 protected:
  FrontendTest()
      : test_db_(),
        test_signer_(),
        verifier_(new LogVerifier(TestSigner::DefaultLogSigVerifier(),
                                  new MerkleVerifier(new Sha256Hasher()))),
        checker_(),
        frontend_(new FE(new CertSubmissionHandler(&checker_),
                         new FrontendSigner(db(),
                                            TestSigner::DefaultLogSigner()))) {}

  void SetUp() {
    cert_dir_ = FLAGS_test_certs_dir;
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kLeafCert, &leaf_pem_))
        << "Could not read test data from " << cert_dir_
        << ". Wrong --test_certs_dir?";
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kCaPreCert, &ca_precert_pem_));
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kPreCert, &precert_pem_));
    CHECK(util::ReadBinaryFile(cert_dir_ + "/" + kPreWithPreCaCert,
                               &precert_with_preca_pem_));
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kIntermediateCert,
                             &intermediate_pem_));
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kChainLeafCert,
                             &chain_leaf_pem_));
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kCaCert, &ca_pem_));
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kEmbeddedCert,  &embedded_pem_));
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kEmbeddedWithPreCaCert,
                             &embedded_with_preca_pem_));
    CHECK(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert));
  }

  void CompareStats(const FE::FrontendStats &expected) {
    FE::FrontendStats stats;
    frontend_->GetStats(&stats);
    EXPECT_EQ(expected.x509_accepted, stats.x509_accepted);
    EXPECT_EQ(expected.x509_duplicates, stats.x509_duplicates);
    EXPECT_EQ(expected.x509_bad_pem_certs, stats.x509_bad_pem_certs);
    EXPECT_EQ(expected.x509_too_long_certs, stats.x509_too_long_certs);
    EXPECT_EQ(expected.x509_verify_errors, stats.x509_verify_errors);
    EXPECT_EQ(expected.precert_accepted, stats.precert_accepted);
    EXPECT_EQ(expected.precert_duplicates, stats.precert_duplicates);
    EXPECT_EQ(expected.precert_bad_pem_certs, stats.precert_bad_pem_certs);
    EXPECT_EQ(expected.precert_too_long_certs, stats.precert_too_long_certs);
    EXPECT_EQ(expected.precert_verify_errors, stats.precert_verify_errors);
    EXPECT_EQ(expected.precert_format_errors, stats.precert_format_errors);
    EXPECT_EQ(expected.internal_errors, stats.internal_errors);
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
  FE *frontend_;
  string cert_dir_;
  string leaf_pem_;
  string ca_precert_pem_;
  string precert_pem_;
  string precert_with_preca_pem_;
  string intermediate_pem_;
  string chain_leaf_pem_;
  string embedded_pem_;
  string embedded_with_preca_pem_;
  string ca_pem_;
};

typedef testing::Types<FileDB<LoggedCertificate>,
                       SQLiteDB<LoggedCertificate> > Databases;

TYPED_TEST_CASE(FrontendTest, Databases);

TYPED_TEST(FrontendTest, TestSubmitValid) {
  CertChain chain(this->leaf_pem_);
  EXPECT_TRUE(chain.IsLoaded());

  SignedCertificateTimestamp sct;
  EXPECT_EQ(ADDED, this->frontend_->QueueX509Entry(&chain, &sct));

  // Look it up and expect to get the right thing back.
  LoggedCertificate logged_cert;
  Cert cert(this->leaf_pem_);

  string sha256_digest;
  ASSERT_EQ(Cert::TRUE, cert.Sha256Digest(&sha256_digest));
  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LookupByHash(sha256_digest,
                                                    &logged_cert));

  EXPECT_EQ(ct::X509_ENTRY, logged_cert.entry().type());
  // Compare the leaf cert.
  string der_string;
  ASSERT_EQ(Cert::TRUE, cert.DerEncoding(&der_string));
  EXPECT_EQ(H(der_string),
            H(logged_cert.entry().x509_entry().leaf_certificate()));

  // And verify the signature.
  EXPECT_EQ(LogVerifier::VERIFY_OK,
            this->verifier_->VerifySignedCertificateTimestamp(
                logged_cert.entry(), sct));

  FE::FrontendStats stats(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  this->CompareStats(stats);
}

TYPED_TEST(FrontendTest, TestSubmitValidWithIntermediate) {
  CertChain chain(this->chain_leaf_pem_ + this->intermediate_pem_);
  EXPECT_TRUE(chain.IsLoaded());

  SignedCertificateTimestamp sct;
  EXPECT_EQ(ADDED, this->frontend_->QueueX509Entry(&chain, &sct));

  // Look it up and expect to get the right thing back.
  LoggedCertificate logged_cert;
  Cert cert(this->chain_leaf_pem_);

  string sha256_digest;
  ASSERT_EQ(Cert::TRUE, cert.Sha256Digest(&sha256_digest));
  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LookupByHash(sha256_digest,
                                                    &logged_cert));

  EXPECT_EQ(ct::X509_ENTRY, logged_cert.entry().type());
  // Compare the leaf cert.
  string der_string;
  ASSERT_EQ(Cert::TRUE, cert.DerEncoding(&der_string));
  EXPECT_EQ(H(der_string),
            H(logged_cert.entry().x509_entry().leaf_certificate()));

  // And verify the signature.
  EXPECT_EQ(LogVerifier::VERIFY_OK,
            this->verifier_->VerifySignedCertificateTimestamp(
                logged_cert.entry(), sct));

  // Compare the first intermediate.
  ASSERT_GE(logged_cert.entry().x509_entry().certificate_chain_size(), 1);
  Cert cert2(this->intermediate_pem_);

  ASSERT_EQ(Cert::TRUE, cert2.DerEncoding(&der_string));
  EXPECT_EQ(H(der_string),
            H(logged_cert.entry().x509_entry().certificate_chain(0)));
  FE::FrontendStats stats(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  this->CompareStats(stats);
}

TYPED_TEST(FrontendTest, TestSubmitDuplicate) {
  CertChain chain1(this->leaf_pem_);
  CertChain chain2(this->leaf_pem_);
  EXPECT_TRUE(chain1.IsLoaded());
  EXPECT_TRUE(chain2.IsLoaded());

  SignedCertificateTimestamp sct;
  EXPECT_EQ(ADDED, this->frontend_->QueueX509Entry(&chain1, NULL));
  EXPECT_EQ(DUPLICATE, this->frontend_->QueueX509Entry(&chain2, &sct));

  // Look it up and expect to get the right thing back.
  LoggedCertificate logged_cert;
  Cert cert(this->leaf_pem_);

  string sha256_digest;
  ASSERT_EQ(Cert::TRUE, cert.Sha256Digest(&sha256_digest));
  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LookupByHash(sha256_digest,
                                                    &logged_cert));

  EXPECT_EQ(ct::X509_ENTRY, logged_cert.entry().type());
  // Compare the leaf cert.
  string der_string;
  ASSERT_EQ(Cert::TRUE, cert.DerEncoding(&der_string));
  EXPECT_EQ(H(der_string),
            H(logged_cert.entry().x509_entry().leaf_certificate()));

  // And verify the signature.
  EXPECT_EQ(LogVerifier::VERIFY_OK,
            this->verifier_->VerifySignedCertificateTimestamp(
                logged_cert.entry(), sct));
  FE::FrontendStats stats(1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  this->CompareStats(stats);
}

TYPED_TEST(FrontendTest, TestSubmitInvalidChain) {
  CertChain chain(this->chain_leaf_pem_);
  EXPECT_TRUE(chain.IsLoaded());

  SignedCertificateTimestamp sct;
  // Missing intermediate.
  EXPECT_EQ(CERTIFICATE_VERIFY_ERROR,
            this->frontend_->QueueX509Entry(&chain, &sct));
  EXPECT_FALSE(sct.has_signature());
  FE::FrontendStats stats(0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0);
  this->CompareStats(stats);
}

TYPED_TEST(FrontendTest, TestSubmitInvalidPem) {
  CertChain chain("-----BEGIN CERTIFICATE-----\n"
                  "Iamnotavalidcert\n"
                  "-----END CERTIFICATE-----\n");
  EXPECT_FALSE(chain.IsLoaded());

  SignedCertificateTimestamp sct;
  EXPECT_EQ(BAD_PEM_FORMAT, this->frontend_->QueueX509Entry(&chain, &sct));
  EXPECT_FALSE(sct.has_signature());
  FE::FrontendStats stats(0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  this->CompareStats(stats);
}

TYPED_TEST(FrontendTest, TestSubmitPrecert) {
  PreCertChain submission(this->precert_pem_);
  EXPECT_TRUE(submission.IsLoaded());

  SignedCertificateTimestamp sct;
  EXPECT_EQ(ADDED, this->frontend_->QueuePreCertEntry(&submission, &sct));

  CertChain chain(this->embedded_pem_ + this->ca_pem_);
  LogEntry entry;
  CertSubmissionHandler::X509ChainToEntry(chain, &entry);

  // Look it up.
  string hash = Sha256Hasher::Sha256Digest(
      entry.precert_entry().pre_cert().tbs_certificate());
  LoggedCertificate logged_cert;
  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LookupByHash(hash, &logged_cert));
  Cert pre(this->precert_pem_);
  Cert ca(this->ca_pem_);

  EXPECT_EQ(ct::PRECERT_ENTRY, logged_cert.entry().type());
  // Verify the signature.
  EXPECT_EQ(LogVerifier::VERIFY_OK,
            this->verifier_->VerifySignedCertificateTimestamp(
                logged_cert.entry(), sct));

  // Expect to have the original certs logged in the chain.
  ASSERT_EQ(logged_cert.entry().precert_entry().precertificate_chain_size(), 1);

  string pre_der, ca_der;
  ASSERT_EQ(Cert::TRUE, pre.DerEncoding(&pre_der));
  ASSERT_EQ(Cert::TRUE, ca.DerEncoding(&ca_der));

  EXPECT_EQ(H(pre_der),
            H(logged_cert.entry().precert_entry().pre_certificate()));
  EXPECT_EQ(H(ca_der),
            H(logged_cert.entry().precert_entry().precertificate_chain(0)));
  Frontend::FrontendStats stats(0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0);
  this->CompareStats(stats);
}

TYPED_TEST(FrontendTest, TestSubmitPrecertUsingPreCA) {
  PreCertChain submission(
      this->precert_with_preca_pem_ + this->ca_precert_pem_);
  EXPECT_TRUE(submission.IsLoaded());

  SignedCertificateTimestamp sct;
  EXPECT_EQ(ADDED, this->frontend_->QueuePreCertEntry(&submission, &sct));

  CertChain chain(this->embedded_with_preca_pem_ + this->ca_pem_);
  LogEntry entry;
  CertSubmissionHandler::X509ChainToEntry(chain, &entry);

  // Look it up.
  string hash = Sha256Hasher::Sha256Digest(
      entry.precert_entry().pre_cert().tbs_certificate());
  LoggedCertificate logged_cert;
  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LookupByHash(hash, &logged_cert));
  Cert pre(this->precert_with_preca_pem_);
  Cert ca_pre(this->ca_precert_pem_);
  Cert ca(this->ca_pem_);

  EXPECT_EQ(ct::PRECERT_ENTRY, logged_cert.entry().type());
  // Verify the signature.
  EXPECT_EQ(LogVerifier::VERIFY_OK,
            this->verifier_->VerifySignedCertificateTimestamp(
                logged_cert.entry(), sct));

  // Expect to have the original certs logged in the chain.
  ASSERT_GE(logged_cert.entry().precert_entry().precertificate_chain_size(), 2);

  string pre_der, ca_der, ca_pre_der;
  ASSERT_EQ(Cert::TRUE, pre.DerEncoding(&pre_der));
  ASSERT_EQ(Cert::TRUE, ca.DerEncoding(&ca_der));
  ASSERT_EQ(Cert::TRUE, ca_pre.DerEncoding(&ca_pre_der));

  EXPECT_EQ(H(pre_der),
            H(logged_cert.entry().precert_entry().pre_certificate()));
  EXPECT_EQ(H(ca_pre_der),
            H(logged_cert.entry().precert_entry().precertificate_chain(0)));
  EXPECT_EQ(H(ca_der),
            H(logged_cert.entry().precert_entry().precertificate_chain(1)));
  FE::FrontendStats stats(0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0);
  this->CompareStats(stats);
}

}  // namespace

int main(int argc, char **argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  cert_trans::LoadCtExtensions();
  return RUN_ALL_TESTS();
}
