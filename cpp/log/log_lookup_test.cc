/* -*- indent-tabs-mode: nil -*- */
#include <gtest/gtest.h>
#include <string>

#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/log_lookup.h"
#include "log/log_signer.h"
#include "log/log_verifier.h"
#include "log/logged_certificate.h"
#include "log/sqlite_db.h"
#include "log/test_db.h"
#include "log/test_signer.h"
#include "log/tree_signer.h"
#include "merkletree/merkle_verifier.h"
#include "merkletree/serial_hasher.h"
#include "util/testing.h"
#include "util/util.h"

namespace {

using cert_trans::LoggedCertificate;
using ct::MerkleAuditProof;
using std::string;

typedef Database<LoggedCertificate> DB;
typedef TreeSigner<LoggedCertificate> TS;
typedef LogLookup<LoggedCertificate> LL;

template <class T> class LogLookupTest : public ::testing::Test {
 protected:
  LogLookupTest()
      : test_db_(),
        test_signer_(),
        tree_signer_(NULL),
        verifier_(NULL) {}

  void SetUp() {
    verifier_ = new LogVerifier(TestSigner::DefaultLogSigVerifier(),
                                new MerkleVerifier(new Sha256Hasher()));
    tree_signer_ = new TS(db(), TestSigner::DefaultLogSigner());
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
  TS *tree_signer_;
  LogVerifier *verifier_;
};

typedef testing::Types<FileDB<LoggedCertificate>,
                       SQLiteDB<LoggedCertificate> > Databases;

TYPED_TEST_CASE(LogLookupTest, Databases);

TYPED_TEST(LogLookupTest, Lookup) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));

  MerkleAuditProof proof;
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  LL lookup(this->db());
  // Look the new entry up.
  EXPECT_EQ(LL::OK, lookup.AuditProof(logged_cert.merkle_leaf_hash(), &proof));
}

TYPED_TEST(LogLookupTest, NotFound) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));

  MerkleAuditProof proof;
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  LL lookup(this->db());

  // Look up using a wrong hash.
  string hash = this->test_signer_.UniqueHash();
  EXPECT_EQ(LL::NOT_FOUND, lookup.AuditProof(hash, &proof));
}

TYPED_TEST(LogLookupTest, Update) {
  LL lookup(this->db());
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));

  MerkleAuditProof proof;
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  // There is an entry but we don't know about it yet.
  EXPECT_EQ(LL::NOT_FOUND, lookup.AuditProof(logged_cert.merkle_leaf_hash(),
                                             &proof));

  // Update
  EXPECT_EQ(LL::UPDATE_OK, lookup.Update());
  // Look the new entry up.
  EXPECT_EQ(LL::OK, lookup.AuditProof(logged_cert.merkle_leaf_hash(), &proof));
}

// Verify that the audit proof constructed is correct (assuming the signer
// operates correctly). TODO(ekasper): KAT tests.
TYPED_TEST(LogLookupTest, Verify) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));

  MerkleAuditProof proof;
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  LL lookup(this->db());
  // Look the new entry up.
  EXPECT_EQ(LL::OK, lookup.AuditProof(logged_cert.merkle_leaf_hash(), &proof));
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
    EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_certs[i]));
  }

  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  LL lookup(this->db());
  MerkleAuditProof proof;

  for (int i = 0; i < 13; ++i) {
    EXPECT_EQ(LL::OK, lookup.AuditProof(logged_certs[i].merkle_leaf_hash(),
                                        &proof));
    EXPECT_EQ(LogVerifier::VERIFY_OK,
              this->verifier_->VerifyMerkleAuditProof(
                  logged_certs[i].entry(),
                  logged_certs[i].sct(), proof));
  }
}

}  // namespace

int main(int argc, char**argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
