/* -*- indent-tabs-mode: nil -*- */
#include <gtest/gtest.h>
#include <stdint.h>
#include <string>

#include "log/file_db.h"
#include "log/log_signer.h"
#include "log/log_verifier.h"
#include "log/sqlite_db.h"
#include "log/test_db.h"
#include "log/test_signer.h"
#include "log/tree_signer.h"
#include "merkletree/merkle_verifier.h"
#include "proto/ct.pb.h"
#include "util/testing.h"
#include "util/util.h"

namespace {

using cert_trans::LoggedCertificate;
using ct::SignedTreeHead;
using std::string;

typedef Database<LoggedCertificate> DB;
typedef TreeSigner<LoggedCertificate> TS;

template <class T> class TreeSignerTest : public ::testing::Test {
 protected:
  TreeSignerTest()
      : test_db_(),
        test_signer_(),
        verifier_(NULL),
        tree_signer_(NULL) {}

  void SetUp() {
    verifier_ = new LogVerifier(TestSigner::DefaultLogSigVerifier(),
                                new MerkleVerifier(new Sha256Hasher()));
    tree_signer_ = new TS(db(), TestSigner::DefaultLogSigner());
  }

  TS *GetSimilar() const {
    return new TS(db(), TestSigner::DefaultLogSigner());
  }

  ~TreeSignerTest() {
    delete verifier_;
    delete tree_signer_;
  }

  T *db() const { return test_db_.db(); }
  TestDB<T> test_db_;
  TestSigner test_signer_;
  LogVerifier *verifier_;
  TS *tree_signer_;
};

typedef testing::Types<FileDB<LoggedCertificate>,
                       SQLiteDB<LoggedCertificate> > Databases;

TYPED_TEST_CASE(TreeSignerTest, Databases);

// TODO(ekasper): KAT tests.
TYPED_TEST(TreeSignerTest, Sign) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));

  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  SignedTreeHead sth;
  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LatestTreeHead(&sth));
  EXPECT_EQ(1U, sth.tree_size());
  EXPECT_EQ(sth.timestamp(), this->tree_signer_->LastUpdateTime());
}

TYPED_TEST(TreeSignerTest, Timestamp) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));

  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());
  uint64_t last_update = this->tree_signer_->LastUpdateTime();
  EXPECT_GE(last_update, logged_cert.sct().timestamp());

  // Now create a second entry with a timestamp some time in the future
  // and verify that the signer's timestamp is greater than that.
  uint64_t future = last_update + 10000;
  LoggedCertificate logged_cert2;
  this->test_signer_.CreateUnique(&logged_cert2);
  logged_cert2.mutable_sct()->set_timestamp(future);
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert2));

  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());
  EXPECT_GE(this->tree_signer_->LastUpdateTime(), future);
}

TYPED_TEST(TreeSignerTest, Verify) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));

  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  SignedTreeHead sth;
  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LatestTreeHead(&sth));
  EXPECT_EQ(LogVerifier::VERIFY_OK, this->verifier_->VerifySignedTreeHead(sth));
}

TYPED_TEST(TreeSignerTest, ResumeClean) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));

  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());
  SignedTreeHead sth;

  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LatestTreeHead(&sth));

  TS *signer2 = this->GetSimilar();
  EXPECT_EQ(signer2->LastUpdateTime(), sth.timestamp());

  // Update
  EXPECT_EQ(TS::OK, signer2->UpdateTree());
  SignedTreeHead sth2;

  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LatestTreeHead(&sth2));
  EXPECT_LT(sth.timestamp(), sth2.timestamp());
  EXPECT_EQ(sth.sha256_root_hash(), sth2.sha256_root_hash());
  EXPECT_EQ(sth.tree_size(), sth2.tree_size());

  delete signer2;
}

// Test resuming when the tree head signature is lagging behind the
// sequence number commits.
TYPED_TEST(TreeSignerTest, ResumePartialSign) {
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());
  SignedTreeHead sth;
  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LatestTreeHead(&sth));

  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));

  // Simulate the case where we assign a sequence number but fail
  // before signing.
  EXPECT_EQ(DB::OK, this->db()->AssignSequenceNumber(logged_cert.Hash(), 0));

  TS *signer2 = this->GetSimilar();
  EXPECT_EQ(TS::OK, signer2->UpdateTree());
  SignedTreeHead sth2;
  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LatestTreeHead(&sth2));
  // The signer should have picked up the sequence number commit.
  EXPECT_EQ(1U, sth2.tree_size());
  EXPECT_LT(sth.timestamp(), sth2.timestamp());
  EXPECT_NE(sth.sha256_root_hash(), sth2.sha256_root_hash());

  delete signer2;
}

TYPED_TEST(TreeSignerTest, SignEmpty) {
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());
  SignedTreeHead sth;

  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LatestTreeHead(&sth));
  EXPECT_GT(sth.timestamp(), 0U);
  EXPECT_EQ(sth.tree_size(), 0U);
}

TYPED_TEST(TreeSignerTest, FailInconsistentTreeHead) {
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());
  // A second signer interferes.
  TS *signer2 = this->GetSimilar();
  EXPECT_EQ(TS::OK, signer2->UpdateTree());
  // The first signer should detect this and refuse to update.
  EXPECT_EQ(TS::DB_ERROR, this->tree_signer_->UpdateTree());

  delete signer2;
}

TYPED_TEST(TreeSignerTest, FailInconsistentSequenceNumbers) {
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));

  // Assign a sequence number the signer does not know about.
  EXPECT_EQ(DB::OK, this->db()->AssignSequenceNumber(logged_cert.Hash(), 0));

  // Create another pending entry.
  LoggedCertificate logged_cert2;
  this->test_signer_.CreateUnique(&logged_cert2);
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert2));

  // Update should fail because we cannot commit a sequence number.
  EXPECT_EQ(TS::DB_ERROR, this->tree_signer_->UpdateTree());
}

}  // namespace

int main(int argc, char **argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
