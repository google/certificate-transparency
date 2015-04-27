/* -*- indent-tabs-mode: nil -*- */
#include <gtest/gtest.h>
#include <set>
#include <string>

#include "log/database.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/logged_certificate.h"
#include "log/sqlite_db.h"
#include "log/test_db.h"
#include "log/test_signer.h"
#include "util/testing.h"
#include "util/util.h"

// TODO(benl): Introduce a test |Logged| type.

namespace {

using cert_trans::LoggedCertificate;
using ct::SignedTreeHead;
using std::string;


template <class T>
class DBTest : public ::testing::Test {
 protected:
  DBTest() : test_db_(), test_signer_() {
  }

  ~DBTest() {
  }

  T* db() const {
    return test_db_.db();
  }

  TestDB<T> test_db_;
  TestSigner test_signer_;
};

typedef testing::Types<FileDB<cert_trans::LoggedCertificate>,
                       SQLiteDB<cert_trans::LoggedCertificate> > Databases;

typedef Database<cert_trans::LoggedCertificate> DB;

TYPED_TEST_CASE(DBTest, Databases);


TYPED_TEST(DBTest, CreateSequenced) {
  LoggedCertificate logged_cert, lookup_cert;
  this->test_signer_.CreateUnique(&logged_cert);

  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));

  EXPECT_EQ(DB::LOOKUP_OK,
            this->db()->LookupByHash(logged_cert.Hash(), &lookup_cert));
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  lookup_cert.Clear();
  EXPECT_EQ(DB::LOOKUP_OK,
            this->db()->LookupByIndex(logged_cert.sequence_number(),
                                      &lookup_cert));
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  string similar_hash = logged_cert.Hash();
  similar_hash[similar_hash.size() - 1] ^= 1;

  EXPECT_EQ(DB::NOT_FOUND,
            this->db()->LookupByHash(similar_hash, &lookup_cert));
  EXPECT_EQ(DB::NOT_FOUND,
            this->db()->LookupByHash(this->test_signer_.UniqueHash(),
                                     &lookup_cert));
}


TYPED_TEST(DBTest, CreateSequencedDuplicateEntry) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);

  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));

  LoggedCertificate duplicate_cert;
  duplicate_cert.CopyFrom(logged_cert);
  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(duplicate_cert));

  LoggedCertificate lookup_cert;
  EXPECT_EQ(DB::LOOKUP_OK,
            this->db()->LookupByHash(logged_cert.Hash(), &lookup_cert));
  // Check that we get the original entry back.
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  lookup_cert.Clear();
  EXPECT_EQ(DB::LOOKUP_OK,
            this->db()->LookupByIndex(logged_cert.sequence_number(),
                                      &lookup_cert));
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);
}


TYPED_TEST(DBTest, CreateSequencedDuplicateEntryNewSequenceNumber) {
  LoggedCertificate logged_cert, duplicate_cert, lookup_cert;
  this->test_signer_.CreateUnique(&logged_cert);

  duplicate_cert.CopyFrom(logged_cert);
  // Change the timestamp so that we can check that we get the right thing
  // back.
  duplicate_cert.mutable_sct()->set_timestamp(logged_cert.sct().timestamp() +
                                              1000);
  logged_cert.set_sequence_number(1);

  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));

  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(duplicate_cert));

  EXPECT_EQ(DB::LOOKUP_OK,
            this->db()->LookupByHash(logged_cert.Hash(), &lookup_cert));
  // Check that we get the original entry back.
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  // Check that we can find it by sequence number too:
  lookup_cert.Clear();
  EXPECT_EQ(DB::LOOKUP_OK,
            this->db()->LookupByIndex(logged_cert.sequence_number(),
                                      &lookup_cert));

  // And that we can find the duplicate ok as well:
  lookup_cert.Clear();
  EXPECT_EQ(DB::LOOKUP_OK,
            this->db()->LookupByIndex(duplicate_cert.sequence_number(),
                                      &lookup_cert));
  TestSigner::TestEqualLoggedCerts(duplicate_cert, lookup_cert);
}


TYPED_TEST(DBTest, CreateSequencedDuplicateSequenceNumber) {
  LoggedCertificate logged_cert, duplicate_seq, lookup_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  this->test_signer_.CreateUnique(&duplicate_seq);
  duplicate_seq.set_sequence_number(logged_cert.sequence_number());

  // Change the timestamp so that we can check that we get the right thing
  // back.
  duplicate_seq.mutable_sct()->set_timestamp(logged_cert.sct().timestamp() +
                                             1000);

  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));

  EXPECT_EQ(DB::SEQUENCE_NUMBER_ALREADY_IN_USE,
            this->db()->CreateSequencedEntry(duplicate_seq));

  EXPECT_EQ(DB::LOOKUP_OK,
            this->db()->LookupByIndex(logged_cert.sequence_number(),
                                      &lookup_cert));
  // Check that we get the original entry back.
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  lookup_cert.Clear();
  EXPECT_EQ(DB::LOOKUP_OK,
            this->db()->LookupByIndex(logged_cert.sequence_number(),
                                      &lookup_cert));
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);
}


TYPED_TEST(DBTest, TreeSize) {
  LoggedCertificate logged_cert;

  this->test_signer_.CreateUnique(&logged_cert);
  logged_cert.set_sequence_number(0);
  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));
  EXPECT_EQ(1, this->db()->TreeSize());

  this->test_signer_.CreateUnique(&logged_cert);
  logged_cert.set_sequence_number(1);
  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));
  EXPECT_EQ(2, this->db()->TreeSize());

  // Create a gap, this will not increase the tree size.
  this->test_signer_.CreateUnique(&logged_cert);
  logged_cert.set_sequence_number(4);
  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));
  EXPECT_EQ(2, this->db()->TreeSize());

  // Contiguous with the previous one, but still after the gap, so no
  // change in tree size.
  this->test_signer_.CreateUnique(&logged_cert);
  logged_cert.set_sequence_number(3);
  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));
  EXPECT_EQ(2, this->db()->TreeSize());

  // Another gap.
  this->test_signer_.CreateUnique(&logged_cert);
  logged_cert.set_sequence_number(6);
  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));
  EXPECT_EQ(2, this->db()->TreeSize());

  // This fills the first gap, but not the second.
  this->test_signer_.CreateUnique(&logged_cert);
  logged_cert.set_sequence_number(2);
  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));
  EXPECT_EQ(5, this->db()->TreeSize());

  // Now all the gaps are filled.
  this->test_signer_.CreateUnique(&logged_cert);
  logged_cert.set_sequence_number(5);
  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));
  EXPECT_EQ(7, this->db()->TreeSize());
}


TYPED_TEST(DBTest, LookupBySequenceNumber) {
  LoggedCertificate logged_cert, logged_cert2, lookup_cert, lookup_cert2;
  this->test_signer_.CreateUnique(&logged_cert);
  logged_cert.set_sequence_number(42);
  this->test_signer_.CreateUnique(&logged_cert2);
  logged_cert2.set_sequence_number(22);

  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));
  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert2));

  EXPECT_EQ(DB::NOT_FOUND, this->db()->LookupByIndex(23, &lookup_cert));

  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LookupByIndex(42, &lookup_cert));
  EXPECT_EQ(42U, lookup_cert.sequence_number());

  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LookupByIndex(22, &lookup_cert2));
  EXPECT_EQ(22U, lookup_cert2.sequence_number());

  TestSigner::TestEqualLoggedCerts(logged_cert2, lookup_cert2);
}


TYPED_TEST(DBTest, WriteTreeHead) {
  SignedTreeHead sth, lookup_sth;
  this->test_signer_.CreateUnique(&sth);

  EXPECT_EQ(DB::NOT_FOUND, this->db()->LatestTreeHead(&lookup_sth));
  EXPECT_EQ(DB::OK, this->db()->WriteTreeHead(sth));
  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LatestTreeHead(&lookup_sth));
  TestSigner::TestEqualTreeHeads(sth, lookup_sth);
}


TYPED_TEST(DBTest, WriteTreeHeadDuplicateTimestamp) {
  SignedTreeHead sth, sth2, lookup_sth;
  this->test_signer_.CreateUnique(&sth);

  EXPECT_EQ(DB::OK, this->db()->WriteTreeHead(sth));

  sth2.CopyFrom(sth);
  sth2.set_tree_size(sth.tree_size() + 1);
  EXPECT_EQ(DB::DUPLICATE_TREE_HEAD_TIMESTAMP,
            this->db()->WriteTreeHead(sth2));

  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LatestTreeHead(&lookup_sth));
  TestSigner::TestEqualTreeHeads(sth, lookup_sth);
}


TYPED_TEST(DBTest, WriteTreeHeadNewerTimestamp) {
  SignedTreeHead sth, sth2, lookup_sth;
  this->test_signer_.CreateUnique(&sth);
  this->test_signer_.CreateUnique(&sth2);
  // Should be newer already but don't rely on this.
  sth2.set_timestamp(sth.timestamp() + 1000);

  EXPECT_EQ(DB::OK, this->db()->WriteTreeHead(sth));
  EXPECT_EQ(DB::OK, this->db()->WriteTreeHead(sth2));

  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LatestTreeHead(&lookup_sth));
  TestSigner::TestEqualTreeHeads(sth2, lookup_sth);
}


TYPED_TEST(DBTest, WriteTreeHeadOlderTimestamp) {
  SignedTreeHead sth, sth2, lookup_sth;
  this->test_signer_.CreateUnique(&sth);
  this->test_signer_.CreateUnique(&sth2);
  // Should be newer already but don't rely on this.
  sth2.set_timestamp(sth.timestamp() - 1000);

  EXPECT_EQ(DB::OK, this->db()->WriteTreeHead(sth));
  EXPECT_EQ(DB::OK, this->db()->WriteTreeHead(sth2));

  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LatestTreeHead(&lookup_sth));
  TestSigner::TestEqualTreeHeads(sth, lookup_sth);
}


TYPED_TEST(DBTest, Resume) {
  LoggedCertificate logged_cert, logged_cert2, lookup_cert, lookup_cert2;
  this->test_signer_.CreateUnique(&logged_cert);
  logged_cert.set_sequence_number(42);
  this->test_signer_.CreateUnique(&logged_cert2);
  logged_cert2.set_sequence_number(22);

  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert));
  EXPECT_EQ(DB::OK, this->db()->CreateSequencedEntry(logged_cert2));

  SignedTreeHead sth, sth2, lookup_sth;
  this->test_signer_.CreateUnique(&sth);
  this->test_signer_.CreateUnique(&sth2);
  sth2.set_timestamp(sth.timestamp() - 1000);
  EXPECT_EQ(DB::OK, this->db()->WriteTreeHead(sth));
  EXPECT_EQ(DB::OK, this->db()->WriteTreeHead(sth2));

  Database<cert_trans::LoggedCertificate>* db2 = this->test_db_.SecondDB();

  EXPECT_EQ(DB::LOOKUP_OK,
            db2->LookupByHash(logged_cert.Hash(), &lookup_cert));
  EXPECT_EQ(42U, lookup_cert.sequence_number());

  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  EXPECT_EQ(DB::LOOKUP_OK,
            db2->LookupByHash(logged_cert2.Hash(), &lookup_cert2));
  EXPECT_EQ(22U, lookup_cert2.sequence_number());

  TestSigner::TestEqualLoggedCerts(logged_cert2, lookup_cert2);

  EXPECT_EQ(DB::LOOKUP_OK, db2->LatestTreeHead(&lookup_sth));
  TestSigner::TestEqualTreeHeads(sth, lookup_sth);

  delete db2;
}


TYPED_TEST(DBTest, ResumeEmpty) {
  DB* db2 = this->test_db_.SecondDB();

  LoggedCertificate lookup_cert;
  EXPECT_EQ(DB::NOT_FOUND, db2->LookupByIndex(0, &lookup_cert));

  SignedTreeHead lookup_sth;
  EXPECT_EQ(DB::NOT_FOUND, db2->LatestTreeHead(&lookup_sth));

  delete db2;
}


TYPED_TEST(DBTest, NodeId) {
  const string kNodeId("node_id");
  this->db()->InitializeNode(kNodeId);
  std::string id_from_db;
  EXPECT_EQ(DB::LOOKUP_OK, this->db()->NodeId(&id_from_db));
  EXPECT_EQ(kNodeId, id_from_db);
}


TYPED_TEST(DBTest, NoNodeIdSet) {
  std::string id_from_db;
  EXPECT_EQ(DB::NOT_FOUND, this->db()->NodeId(&id_from_db));
}


TYPED_TEST(DBTest, CannotOverwriteNodeId) {
  const string kNodeId("some_node_id");
  this->db()->InitializeNode(kNodeId);
  EXPECT_DEATH(this->db()->InitializeNode("something_else"), kNodeId);
}


TYPED_TEST(DBTest, CannotHaveEmptyNodeId) {
  EXPECT_DEATH(this->db()->InitializeNode(""), "empty");
}


}  // namespace


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  return RUN_ALL_TESTS();
}
