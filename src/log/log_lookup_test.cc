#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <string>

#include "file_db.h"
#include "file_storage.h"
#include "log_lookup.h"
#include "log_signer.h"
#include "log_verifier.h"
#include "merkle_verifier.h"
#include "serial_hasher.h"
#include "sqlite_db.h"
#include "test_db.h"
#include "test_signer.h"
#include "testing.h"
#include "tree_signer.h"
#include "util.h"

namespace {

using ct::LoggedCertificate;
using ct::MerkleAuditProof;
using std::string;

template <class T> class LogLookupTest : public ::testing::Test {
 protected:
  LogLookupTest()
      : test_db_(),
        test_signer_(),
        tree_signer_(NULL),
        verifier_(NULL) {}

  void SetUp() {
    verifier_ = new LogVerifier(TestSigner::DefaultVerifier(),
                                new MerkleVerifier(new Sha256Hasher()));
    tree_signer_ = new TreeSigner(db(), TestSigner::DefaultSigner());
    ASSERT_TRUE(verifier_ != NULL);
    ASSERT_TRUE(tree_signer_ != NULL);
  }

  ~LogLookupTest() {
    delete tree_signer_;
    delete verifier_;
  }

  T *db() const { return test_db_.db(); }
  TestDB<T> test_db_;
  TestSigner test_signer_;
  TreeSigner *tree_signer_;
  LogVerifier *verifier_;
};

typedef testing::Types<FileDB, SQLiteDB> Databases;

TYPED_TEST_CASE(LogLookupTest, Databases);

TYPED_TEST(LogLookupTest, Lookup) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert));

  MerkleAuditProof proof;
  EXPECT_EQ(TreeSigner::OK, this->tree_signer_->UpdateTree());

  LogLookup lookup(this->db());
  // Look the new entry up.
  EXPECT_EQ(LogLookup::OK,
            lookup.CertificateAuditProof(logged_cert.sct().timestamp(),
                                         logged_cert.certificate_sha256_hash(),
                                         &proof));
}

TYPED_TEST(LogLookupTest, NotFound) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert));

  MerkleAuditProof proof;
  EXPECT_EQ(TreeSigner::OK, this->tree_signer_->UpdateTree());

  LogLookup lookup(this->db());

  // Look up using a wrong hash.
  string hash = this->test_signer_.UniqueHash();
  EXPECT_EQ(LogLookup::NOT_FOUND,
            lookup.CertificateAuditProof(logged_cert.sct().timestamp(),
                                         hash,
                                         &proof));

  // Wrong timestamp
  EXPECT_EQ(LogLookup::NOT_FOUND,
            lookup.CertificateAuditProof(logged_cert.sct().timestamp()  + 1,
                                         logged_cert.certificate_sha256_hash(),
                                         &proof));
}

TYPED_TEST(LogLookupTest, Update) {
  LogLookup lookup(this->db());
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert));

  MerkleAuditProof proof;
  EXPECT_EQ(TreeSigner::OK, this->tree_signer_->UpdateTree());

  // There is an entry but we don't know about it yet.
  EXPECT_EQ(LogLookup::NOT_FOUND,
            lookup.CertificateAuditProof(logged_cert.sct().timestamp(),
                                         logged_cert.certificate_sha256_hash(),
                                         &proof));

  // Update
  EXPECT_EQ(LogLookup::UPDATE_OK, lookup.Update());
  // Look the new entry up.
  EXPECT_EQ(LogLookup::OK,
            lookup.CertificateAuditProof(logged_cert.sct().timestamp(),
                                         logged_cert.certificate_sha256_hash(),
                                         &proof));
}

// Verify that the audit proof constructed is correct (assuming the signer
// operates correctly). TODO(ekasper): KAT tests.
TYPED_TEST(LogLookupTest, Verify) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert));

  MerkleAuditProof proof;
  EXPECT_EQ(TreeSigner::OK, this->tree_signer_->UpdateTree());

  LogLookup lookup(this->db());
  // Look the new entry up.
  EXPECT_EQ(LogLookup::OK,
            lookup.CertificateAuditProof(logged_cert.sct().timestamp(),
                                         logged_cert.certificate_sha256_hash(),
                                         &proof));
  EXPECT_EQ(LogVerifier::VERIFY_OK,
            this->verifier_->VerifyMerkleAuditProof(logged_cert.entry(),
                                                    logged_cert.sct(), proof));
}

// Build a bigger tree so that we actually verify a non-empty path.
TYPED_TEST(LogLookupTest, VerifyWithPath) {
  LoggedCertificate logged_certs[13];

  // Make the tree not balanced for extra fun.
  for (int i = 0; i < 13; ++i) {
    this->test_signer_.CreateUnique(&logged_certs[i]);
    EXPECT_EQ(Database::OK,
              this->db()->CreatePendingCertificateEntry(logged_certs[i]));
  }

  EXPECT_EQ(TreeSigner::OK, this->tree_signer_->UpdateTree());

  LogLookup lookup(this->db());
  MerkleAuditProof proof;

  for (int i = 0; i < 13; ++i) {
    EXPECT_EQ(LogLookup::OK,
              lookup.CertificateAuditProof(
                  logged_certs[i].sct().timestamp(),
                  logged_certs[i].certificate_sha256_hash(), &proof));
    EXPECT_EQ(LogVerifier::VERIFY_OK,
              this->verifier_->VerifyMerkleAuditProof(
                  logged_certs[i].entry(),
                  logged_certs[i].sct(), proof));
  }
}

}  // namespace

int main(int argc, char**argv) {
  ct::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
