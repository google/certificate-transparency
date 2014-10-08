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

TYPED_TEST(DBTest, CreatePending) {
  LoggedCertificate logged_cert, lookup_cert;
  this->test_signer_.CreateUnique(&logged_cert);

  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));

  EXPECT_EQ(DB::LOOKUP_OK,
            this->db()->LookupByHash(logged_cert.Hash(), &lookup_cert));
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  string similar_hash = logged_cert.Hash();
  similar_hash[similar_hash.size() - 1] ^= 1;

  EXPECT_EQ(DB::NOT_FOUND,
            this->db()->LookupByHash(similar_hash, &lookup_cert));
  EXPECT_EQ(DB::NOT_FOUND,
            this->db()->LookupByHash(this->test_signer_.UniqueHash(),
                                     &lookup_cert));
}

TYPED_TEST(DBTest, GetPendingHashes) {
  LoggedCertificate logged_cert, logged_cert2;
  this->test_signer_.CreateUnique(&logged_cert);
  this->test_signer_.CreateUnique(&logged_cert2);

  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert2));

  std::set<string> hashes;
  hashes.insert(logged_cert.Hash());
  hashes.insert(logged_cert2.Hash());

  std::set<string> pending_hashes = this->db()->PendingHashes();
  EXPECT_EQ(hashes, pending_hashes);
}

TYPED_TEST(DBTest, CreatePendingDuplicate) {
  LoggedCertificate logged_cert, duplicate_cert, lookup_cert;
  this->test_signer_.CreateUnique(&logged_cert);

  duplicate_cert.CopyFrom(logged_cert);
  // Change the timestamp so that we can check that we get the right thing
  // back.
  duplicate_cert.mutable_sct()->set_timestamp(logged_cert.sct().timestamp() +
                                              1000);

  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));

  EXPECT_EQ(DB::DUPLICATE_CERTIFICATE_HASH,
            this->db()->CreatePendingEntry(duplicate_cert));

  EXPECT_EQ(DB::LOOKUP_OK,
            this->db()->LookupByHash(logged_cert.Hash(), &lookup_cert));
  // Check that we get the original entry back.
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);
}

TYPED_TEST(DBTest, AssignSequenceNumber) {
  LoggedCertificate logged_cert, lookup_cert;
  this->test_signer_.CreateUnique(&logged_cert);

  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));
  EXPECT_EQ(DB::OK, this->db()->AssignSequenceNumber(logged_cert.Hash(), 42));

  EXPECT_EQ(DB::LOOKUP_OK,
            this->db()->LookupByHash(logged_cert.Hash(), &lookup_cert));
  EXPECT_EQ(42U, lookup_cert.sequence_number());

  lookup_cert.clear_sequence_number();
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);
}

TYPED_TEST(DBTest, AssignSequenceNumberNotPending) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(DB::ENTRY_NOT_FOUND,
            this->db()->AssignSequenceNumber(logged_cert.Hash(), 0));

  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));
  EXPECT_EQ(DB::OK, this->db()->AssignSequenceNumber(logged_cert.Hash(), 42));

  EXPECT_EQ(DB::ENTRY_ALREADY_LOGGED,
            this->db()->AssignSequenceNumber(logged_cert.Hash(), 42));
}

TYPED_TEST(DBTest, AssignSequenceNumberTwice) {
  LoggedCertificate logged_cert, logged_cert2;
  this->test_signer_.CreateUnique(&logged_cert);
  this->test_signer_.CreateUnique(&logged_cert2);

  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert2));
  EXPECT_EQ(DB::OK, this->db()->AssignSequenceNumber(logged_cert.Hash(), 42));
  EXPECT_EQ(DB::SEQUENCE_NUMBER_ALREADY_IN_USE,
            this->db()->AssignSequenceNumber(logged_cert2.Hash(), 42));
}

TYPED_TEST(DBTest, LookupBySequenceNumber) {
  LoggedCertificate logged_cert, logged_cert2, lookup_cert, lookup_cert2;
  this->test_signer_.CreateUnique(&logged_cert);
  this->test_signer_.CreateUnique(&logged_cert2);

  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert2));
  EXPECT_EQ(DB::OK, this->db()->AssignSequenceNumber(logged_cert.Hash(), 42));
  EXPECT_EQ(DB::OK, this->db()->AssignSequenceNumber(logged_cert2.Hash(), 22));

  EXPECT_EQ(DB::NOT_FOUND, this->db()->LookupByIndex(23, &lookup_cert));

  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LookupByIndex(42, &lookup_cert));
  EXPECT_EQ(42U, lookup_cert.sequence_number());

  lookup_cert.clear_sequence_number();
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  EXPECT_EQ(DB::LOOKUP_OK, this->db()->LookupByIndex(22, &lookup_cert2));
  EXPECT_EQ(22U, lookup_cert2.sequence_number());

  lookup_cert2.clear_sequence_number();
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
  this->test_signer_.CreateUnique(&logged_cert2);

  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert));
  EXPECT_EQ(DB::OK, this->db()->CreatePendingEntry(logged_cert2));
  EXPECT_EQ(DB::OK, this->db()->AssignSequenceNumber(logged_cert.Hash(), 42));

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

  lookup_cert.clear_sequence_number();
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  EXPECT_EQ(DB::LOOKUP_OK,
            db2->LookupByHash(logged_cert2.Hash(), &lookup_cert2));
  TestSigner::TestEqualLoggedCerts(logged_cert2, lookup_cert2);

  EXPECT_EQ(DB::LOOKUP_OK, db2->LatestTreeHead(&lookup_sth));
  TestSigner::TestEqualTreeHeads(sth, lookup_sth);

  std::set<string> pending_hashes;
  pending_hashes.insert(logged_cert2.Hash());

  EXPECT_EQ(pending_hashes, db2->PendingHashes());

  delete db2;
}

TYPED_TEST(DBTest, ResumeEmpty) {
  DB* db2 = this->test_db_.SecondDB();

  LoggedCertificate lookup_cert;
  EXPECT_EQ(DB::NOT_FOUND, db2->LookupByIndex(0, &lookup_cert));

  SignedTreeHead lookup_sth;
  EXPECT_EQ(DB::NOT_FOUND, db2->LatestTreeHead(&lookup_sth));

  EXPECT_TRUE(db2->PendingHashes().empty());

  delete db2;
}

}  // namespace

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
