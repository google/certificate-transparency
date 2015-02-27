/* -*- indent-tabs-mode: nil -*- */
#include <gtest/gtest.h>
#include <memory>
#include <stdint.h>
#include <string>

#include "log/etcd_consistent_store.h"
#include "log/file_db.h"
#include "log/log_signer.h"
#include "log/log_verifier.h"
#include "log/sqlite_db.h"
#include "log/test_db.h"
#include "log/test_signer.h"
#include "log/tree_signer.h"
#include "log/tree_signer-inl.h"
#include "merkletree/merkle_verifier.h"
#include "proto/ct.pb.h"
#include "util/fake_etcd.h"
#include "util/mock_masterelection.h"
#include "util/testing.h"
#include "util/util.h"

namespace cert_trans {

using cert_trans::EntryHandle;
using cert_trans::LoggedCertificate;
using cert_trans::MockMasterElection;
using ct::ClusterNodeState;
using ct::SignedTreeHead;
using std::make_shared;
using std::shared_ptr;
using std::string;
using testing::NiceMock;

typedef Database<LoggedCertificate> DB;
typedef TreeSigner<LoggedCertificate> TS;

// TODO(alcutter): figure out if/how we can keep abstract rather than
// hardcoding LoggedCertificate in here.
template <class T>
class TreeSignerTest : public ::testing::Test {
 protected:
  TreeSignerTest()
      : test_db_(),
        base_(make_shared<libevent::Base>()),
        event_pump_(base_),
        etcd_client_(base_),
        pool_(2),
        test_signer_(),
        verifier_(),
        tree_signer_() {
  }

  void SetUp() {
    test_db_.reset(new TestDB<T>);
    verifier_.reset(new LogVerifier(TestSigner::DefaultLogSigVerifier(),
                                    new MerkleVerifier(new Sha256Hasher())));
    store_.reset(
        new EtcdConsistentStore<LoggedCertificate>(&pool_, &etcd_client_,
                                                   &election_, "/root", "id"));
    tree_signer_.reset(new TS(std::chrono::duration<double>(0), db(),
                              store_.get(), TestSigner::DefaultLogSigner()));
    // Set a default empty STH so that we can call UpdateTree() on the signer.
    store_->SetServingSTH(SignedTreeHead());
  }

  void AddPendingEntry(LoggedCertificate* logged_cert) const {
    logged_cert->clear_sequence_number();
    CHECK(this->store_->AddPendingEntry(logged_cert).ok());
  }

  void AddSequencedEntry(LoggedCertificate* logged_cert, int64_t seq) const {
    logged_cert->clear_sequence_number();
    CHECK(this->store_->AddPendingEntry(logged_cert).ok());
    EntryHandle<LoggedCertificate> entry;
    CHECK(this->store_->GetPendingEntryForHash(logged_cert->Hash(), &entry)
              .ok());
    CHECK(this->store_->AssignSequenceNumber(seq, &entry).ok());
  }

  void ForceAddSequencedEntry(LoggedCertificate* logged_cert,
                              int64_t seq) const {
    // Never do this IRL!
    logged_cert->clear_sequence_number();
    logged_cert->set_provisional_sequence_number(seq);
    this->store_->pending_entries_[util::ToBase64(logged_cert->Hash())]
        .MutableEntry()
        ->CopyFrom(*logged_cert);
    logged_cert->set_sequence_number(seq);
    this->store_->sequenced_entries_[std::to_string(seq)]
        .MutableEntry()
        ->CopyFrom(*logged_cert);
  }

  TS* GetSimilar() {
    return new TS(std::chrono::duration<double>(0), db(), store_.get(),
                  TestSigner::DefaultLogSigner());
  }

  T* db() const {
    return test_db_->db();
  }
  std::unique_ptr<TestDB<T>> test_db_;
  shared_ptr<libevent::Base> base_;
  libevent::EventPumpThread event_pump_;
  FakeEtcdClient etcd_client_;
  ThreadPool pool_;
  NiceMock<MockMasterElection> election_;
  std::unique_ptr<EtcdConsistentStore<LoggedCertificate>> store_;
  TestSigner test_signer_;
  std::unique_ptr<LogVerifier> verifier_;
  std::unique_ptr<TS> tree_signer_;
};

typedef testing::Types<FileDB<LoggedCertificate>, SQLiteDB<LoggedCertificate>>
    Databases;


EntryHandle<LoggedCertificate> H(const LoggedCertificate& l) {
  EntryHandle<LoggedCertificate> handle;
  handle.MutableEntry()->CopyFrom(l);
  return handle;
}


TYPED_TEST_CASE(TreeSignerTest, Databases);

TYPED_TEST(TreeSignerTest, PendingEntriesOrder) {
  PendingEntriesOrder<LoggedCertificate> ordering;
  LoggedCertificate lowest;
  this->test_signer_.CreateUnique(&lowest);
  lowest.set_provisional_sequence_number(1);

  // Can't be lower than itself!
  EXPECT_FALSE(ordering(H(lowest), H(lowest)));

  LoggedCertificate higher_seq(lowest);
  higher_seq.set_provisional_sequence_number(
      lowest.provisional_sequence_number() + 1);
  // lower timestamp should be ignored because of higher sequence number:
  higher_seq.mutable_sct()->set_timestamp(lowest.sct().timestamp() - 1);
  EXPECT_TRUE(ordering(H(lowest), H(higher_seq)));
  EXPECT_FALSE(ordering(H(higher_seq), H(lowest)));

  LoggedCertificate no_seq(lowest);
  no_seq.clear_provisional_sequence_number();
  // sequence number < no sequence number
  EXPECT_TRUE(ordering(H(lowest), H(no_seq)));
  EXPECT_FALSE(ordering(H(no_seq), H(lowest)));

  // check timestamp fallback:
  LoggedCertificate no_seq_higher_timestamp(no_seq);
  no_seq_higher_timestamp.mutable_sct()->set_timestamp(
      no_seq.sct().timestamp() + 1);
  EXPECT_TRUE(ordering(H(no_seq), H(no_seq_higher_timestamp)));
  EXPECT_FALSE(ordering(H(no_seq_higher_timestamp), H(no_seq)));

  // check hash fallback:
  LoggedCertificate no_seq_higher_hash(no_seq);
  while (no_seq_higher_hash.Hash() <= no_seq.Hash()) {
    this->test_signer_.CreateUnique(&no_seq_higher_hash);
    no_seq_higher_hash.clear_provisional_sequence_number();
    no_seq_higher_hash.mutable_sct()->set_timestamp(
        no_seq_higher_hash.timestamp());
  }
  EXPECT_TRUE(ordering(H(no_seq), H(no_seq_higher_hash)));
  EXPECT_FALSE(ordering(H(no_seq_higher_hash), H(no_seq)));
}


// TODO(ekasper): KAT tests.
TYPED_TEST(TreeSignerTest, Sign) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  this->AddPendingEntry(&logged_cert);
  // this->AddSequencedEntry(&logged_cert, 0);
  EXPECT_EQ(util::Status::OK, this->tree_signer_->SequenceNewEntries());
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  const SignedTreeHead sth(this->tree_signer_->LatestSTH());
  EXPECT_EQ(1U, sth.tree_size());
  EXPECT_EQ(sth.timestamp(), this->tree_signer_->LastUpdateTime());
}


TYPED_TEST(TreeSignerTest, Timestamp) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  this->AddSequencedEntry(&logged_cert, 0);

  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());
  uint64_t last_update = this->tree_signer_->LastUpdateTime();
  EXPECT_GE(last_update, logged_cert.sct().timestamp());

  // Now create a second entry with a timestamp some time in the future
  // and verify that the signer's timestamp is greater than that.
  uint64_t future = last_update + 10000;
  LoggedCertificate logged_cert2;
  this->test_signer_.CreateUnique(&logged_cert2);
  logged_cert2.mutable_sct()->set_timestamp(future);
  this->AddSequencedEntry(&logged_cert2, 1);

  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());
  EXPECT_GE(this->tree_signer_->LastUpdateTime(), future);
}


TYPED_TEST(TreeSignerTest, Verify) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  this->AddSequencedEntry(&logged_cert, 0);

  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  const SignedTreeHead sth(this->tree_signer_->LatestSTH());
  EXPECT_EQ(LogVerifier::VERIFY_OK,
            this->verifier_->VerifySignedTreeHead(sth));
}


TYPED_TEST(TreeSignerTest, ResumeClean) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  this->AddSequencedEntry(&logged_cert, 0);

  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());
  const SignedTreeHead sth(this->tree_signer_->LatestSTH());
  {
    // Simulate the caller of UpdateTree() pushing this new tree out to the
    // cluster.
    ClusterNodeState node_state;
    *node_state.mutable_newest_sth() = sth;
    CHECK_EQ(util::Status::OK, this->store_->SetClusterNodeState(node_state));
  }

  TS* signer2 = this->GetSimilar();

  // Update
  EXPECT_EQ(TS::OK, signer2->UpdateTree());

  const SignedTreeHead sth2(signer2->LatestSTH());
  EXPECT_LT(sth.timestamp(), sth2.timestamp());
  EXPECT_EQ(sth.sha256_root_hash(), sth2.sha256_root_hash());
  EXPECT_EQ(sth.tree_size(), sth2.tree_size());

  delete signer2;
}


// Test resuming when the tree head signature is lagging behind the
// sequence number commits.
TYPED_TEST(TreeSignerTest, ResumePartialSign) {
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());
  const SignedTreeHead sth(this->tree_signer_->LatestSTH());
  {
    // Simulate the caller of UpdateTree() pushing this new tree out to the
    // cluster.
    ClusterNodeState node_state;
    *node_state.mutable_newest_sth() = sth;
    CHECK_EQ(util::Status::OK, this->store_->SetClusterNodeState(node_state));
  }

  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  this->AddSequencedEntry(&logged_cert, 0);

  TS* signer2 = this->GetSimilar();
  EXPECT_EQ(TS::OK, signer2->UpdateTree());
  const SignedTreeHead sth2(signer2->LatestSTH());
  // The signer should have picked up the sequence number commit.
  EXPECT_EQ(1U, sth2.tree_size());
  EXPECT_LT(sth.timestamp(), sth2.timestamp());
  EXPECT_NE(sth.sha256_root_hash(), sth2.sha256_root_hash());

  delete signer2;
}


TYPED_TEST(TreeSignerTest, RecoverWithPendingSequenceNumber) {
  LoggedCertificate sequenced_cert;
  this->test_signer_.CreateUnique(&sequenced_cert);
  this->AddSequencedEntry(&sequenced_cert, 0);

  LoggedCertificate provisionally_sequenced_cert;
  this->test_signer_.CreateUnique(&provisionally_sequenced_cert);
  provisionally_sequenced_cert.set_provisional_sequence_number(1);
  this->AddPendingEntry(&provisionally_sequenced_cert);

  EXPECT_EQ(util::Status::OK, this->tree_signer_->SequenceNewEntries());
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  const SignedTreeHead sth(this->tree_signer_->LatestSTH());
  EXPECT_EQ(2U, sth.tree_size());
}


TYPED_TEST(TreeSignerTest, SignEmpty) {
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  const SignedTreeHead sth(this->tree_signer_->LatestSTH());
  EXPECT_GT(sth.timestamp(), 0U);
  EXPECT_EQ(sth.tree_size(), 0U);
}


TYPED_TEST(TreeSignerTest, SignerFallenBehindInReplication) {
  SignedTreeHead sth;
  sth.set_tree_size(13);
  sth.set_timestamp(1000);
  this->store_->SetServingSTH(sth);

  for (int i = sth.tree_size(); i < sth.tree_size() + 3; ++i) {
    LoggedCertificate logged_cert;
    this->test_signer_.CreateUnique(&logged_cert);
    this->AddSequencedEntry(&logged_cert, i);
  }

  EXPECT_EQ(0, this->db()->TreeSize());
  EXPECT_EQ(TS::INSUFFICIENT_DATA, this->tree_signer_->UpdateTree());
}


#if 0
TYPED_TEST(TreeSignerTest, FailInconsistentSequenceNumbers) {
  EXPECT_EQ(TS::OK, this->tree_signer_->UpdateTree());

  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  this->AddSequencedEntry(&logged_cert, 0);

  // Create another entry with a gap in sequence numbers:
  LoggedCertificate logged_cert2;
  this->test_signer_.CreateUnique(&logged_cert2);
  this->ForceAddSequencedEntry(&logged_cert2, 2);

  // Update should fail because we don't have sequential numbers
  EXPECT_EQ(TS::DB_ERROR, this->tree_signer_->UpdateTree());
}
#endif


}  // namespace cert_trans


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
