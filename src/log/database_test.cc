/* -*- indent-tabs-mode: nil -*- */

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <set>
#include <string>

#include "database.h"
#include "file_db.h"
#include "file_storage.h"
#include "sqlite_db.h"
#include "test_db.h"
#include "test_signer.h"
#include "util.h"

namespace {

using ct::DigitallySigned;
using ct::LogEntry;
using ct::LoggedCertificate;
using ct::PrecertChainEntry;
using ct::SignedTreeHead;
using ct::X509ChainEntry;
using std::string;

// A slightly shorter notation for constructing hex strings from binary blobs.
string H(const string &byte_string) {
  return util::HexString(byte_string);
}

template <class T> class DBTest : public ::testing::Test {
 protected:
  DBTest() :
      test_db_(),
      test_signer_() { }

  ~DBTest() {}

  T *db() const { return test_db_.db(); }

  TestDB<T> test_db_;
  TestSigner test_signer_;
};

typedef testing::Types<FileDB, SQLiteDB> Databases;

TYPED_TEST_CASE(DBTest, Databases);

TYPED_TEST(DBTest, CreatePending) {
  LoggedCertificate logged_cert, lookup_cert;
  this->test_signer_.CreateUnique(&logged_cert);

  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert));

  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupCertificateByHash(
                logged_cert.certificate_sha256_hash(), &lookup_cert));
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  string similar_hash = logged_cert.certificate_sha256_hash();
  similar_hash[similar_hash.size() - 1] ^= 1;

  EXPECT_EQ(Database::NOT_FOUND,
            this->db()->LookupCertificateByHash(similar_hash,
                                                &lookup_cert));
  EXPECT_EQ(Database::NOT_FOUND,
            this->db()->LookupCertificateByHash(this->test_signer_.UniqueHash(),
                                                &lookup_cert));
}

TYPED_TEST(DBTest, GetPendingHashes) {
  LoggedCertificate logged_cert, logged_cert2;
  this->test_signer_.CreateUnique(&logged_cert);
  this->test_signer_.CreateUnique(&logged_cert2);

  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert));
  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert2));

  std::set<string> hashes;
  hashes.insert(logged_cert.certificate_sha256_hash());
  hashes.insert(logged_cert2.certificate_sha256_hash());

  std::set<string> pending_hashes = this->db()->PendingHashes();
  EXPECT_EQ(hashes, pending_hashes);
}

TYPED_TEST(DBTest, CreatePendingDuplicate) {
  LoggedCertificate logged_cert, duplicate_cert, lookup_cert;
  this->test_signer_.CreateUnique(&logged_cert);

  duplicate_cert.CopyFrom(logged_cert);
  // Change the timestamp so that we can check that we get the right thing back.
  duplicate_cert.mutable_sct()->set_timestamp(
      logged_cert.sct().timestamp() + 1000);

  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert));

  EXPECT_EQ(Database::DUPLICATE_CERTIFICATE_HASH,
            this->db()->CreatePendingCertificateEntry(duplicate_cert));

  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupCertificateByHash(
                logged_cert.certificate_sha256_hash(), &lookup_cert));
            // Check that we get the original entry back.
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);
}

TYPED_TEST(DBTest, AssignSequenceNumber) {
  LoggedCertificate logged_cert, lookup_cert;
  this->test_signer_.CreateUnique(&logged_cert);

  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert));
  EXPECT_EQ(Database::OK,
            this->db()->AssignCertificateSequenceNumber(
                logged_cert.certificate_sha256_hash(), 42));

  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupCertificateByHash(
                logged_cert.certificate_sha256_hash(), &lookup_cert));
  EXPECT_EQ(42U, lookup_cert.sequence_number());

  lookup_cert.clear_sequence_number();
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);
}

TYPED_TEST(DBTest, AssignSequenceNumberNotPending) {
  LoggedCertificate logged_cert;
  this->test_signer_.CreateUnique(&logged_cert);
  EXPECT_EQ(Database::ENTRY_NOT_FOUND,
            this->db()->AssignCertificateSequenceNumber(
                logged_cert.certificate_sha256_hash(), 0));

  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert));
  EXPECT_EQ(Database::OK,
            this->db()->AssignCertificateSequenceNumber(
                logged_cert.certificate_sha256_hash(), 42));

  EXPECT_EQ(Database::ENTRY_ALREADY_LOGGED,
            this->db()->AssignCertificateSequenceNumber(
                logged_cert.certificate_sha256_hash(), 42));
}

TYPED_TEST(DBTest, AssignSequenceNumberTwice) {
  LoggedCertificate logged_cert, logged_cert2;
  this->test_signer_.CreateUnique(&logged_cert);
  this->test_signer_.CreateUnique(&logged_cert2);

  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert));
  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert2));
  EXPECT_EQ(Database::OK,
            this->db()->AssignCertificateSequenceNumber(
                logged_cert.certificate_sha256_hash(), 42));
  EXPECT_EQ(Database::SEQUENCE_NUMBER_ALREADY_IN_USE,
            this->db()->AssignCertificateSequenceNumber(
                logged_cert2.certificate_sha256_hash(), 42));
}

TYPED_TEST(DBTest, LookupBySequenceNumber) {
  LoggedCertificate logged_cert, logged_cert2, lookup_cert, lookup_cert2;
  this->test_signer_.CreateUnique(&logged_cert);
  this->test_signer_.CreateUnique(&logged_cert2);

  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert));
  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert2));
  EXPECT_EQ(Database::OK,
            this->db()->AssignCertificateSequenceNumber(
                logged_cert.certificate_sha256_hash(), 42));
  EXPECT_EQ(Database::OK,
            this->db()->AssignCertificateSequenceNumber(
                logged_cert2.certificate_sha256_hash(), 22));

  EXPECT_EQ(Database::NOT_FOUND,
            this->db()->LookupCertificateByIndex(23, &lookup_cert));

  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupCertificateByIndex(42, &lookup_cert));
  EXPECT_EQ(42U, lookup_cert.sequence_number());

  lookup_cert.clear_sequence_number();
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupCertificateByIndex(22, &lookup_cert2));
  EXPECT_EQ(22U, lookup_cert2.sequence_number());

  lookup_cert2.clear_sequence_number();
  TestSigner::TestEqualLoggedCerts(logged_cert2, lookup_cert2);
}

TYPED_TEST(DBTest, WriteTreeHead) {
  SignedTreeHead sth, lookup_sth;
  this->test_signer_.CreateUnique(&sth);

  EXPECT_EQ(Database::NOT_FOUND, this->db()->LatestTreeHead(&lookup_sth));

  EXPECT_EQ(Database::OK, this->db()->WriteTreeHead(sth));

  EXPECT_EQ(Database::LOOKUP_OK, this->db()->LatestTreeHead(&lookup_sth));
  TestSigner::TestEqualTreeHeads(sth, lookup_sth);
}

TYPED_TEST(DBTest, WriteTreeHeadDuplicateTimestamp) {
  SignedTreeHead sth, sth2, lookup_sth;
  this->test_signer_.CreateUnique(&sth);

  EXPECT_EQ(Database::OK, this->db()->WriteTreeHead(sth));

  sth2.CopyFrom(sth);
  sth2.set_tree_size(sth.tree_size() + 1);
  EXPECT_EQ(Database::DUPLICATE_TREE_HEAD_TIMESTAMP,
            this->db()->WriteTreeHead(sth2));

  EXPECT_EQ(Database::LOOKUP_OK, this->db()->LatestTreeHead(&lookup_sth));
  TestSigner::TestEqualTreeHeads(sth, lookup_sth);
}

TYPED_TEST(DBTest, WriteTreeHeadNewerTimestamp) {
  SignedTreeHead sth, sth2, lookup_sth;
  this->test_signer_.CreateUnique(&sth);
  this->test_signer_.CreateUnique(&sth2);
  // Should be newer already but don't rely on this.
  sth2.set_timestamp(sth.timestamp() + 1000);

  EXPECT_EQ(Database::OK, this->db()->WriteTreeHead(sth));
  EXPECT_EQ(Database::OK, this->db()->WriteTreeHead(sth2));

  EXPECT_EQ(Database::LOOKUP_OK, this->db()->LatestTreeHead(&lookup_sth));
  TestSigner::TestEqualTreeHeads(sth2, lookup_sth);
}

TYPED_TEST(DBTest, WriteTreeHeadOlderTimestamp) {
  SignedTreeHead sth, sth2, lookup_sth;
  this->test_signer_.CreateUnique(&sth);
  this->test_signer_.CreateUnique(&sth2);
  // Should be newer already but don't rely on this.
  sth2.set_timestamp(sth.timestamp() - 1000);

  EXPECT_EQ(Database::OK, this->db()->WriteTreeHead(sth));
  EXPECT_EQ(Database::OK, this->db()->WriteTreeHead(sth2));

  EXPECT_EQ(Database::LOOKUP_OK, this->db()->LatestTreeHead(&lookup_sth));
  TestSigner::TestEqualTreeHeads(sth, lookup_sth);
}

TYPED_TEST(DBTest, Resume) {
  LoggedCertificate logged_cert, logged_cert2, lookup_cert, lookup_cert2;
  this->test_signer_.CreateUnique(&logged_cert);
  this->test_signer_.CreateUnique(&logged_cert2);

  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert));
  EXPECT_EQ(Database::OK,
            this->db()->CreatePendingCertificateEntry(logged_cert2));
  EXPECT_EQ(Database::OK,
            this->db()->AssignCertificateSequenceNumber(
                logged_cert.certificate_sha256_hash(), 42));

  SignedTreeHead sth, sth2, lookup_sth;
  this->test_signer_.CreateUnique(&sth);
  this->test_signer_.CreateUnique(&sth2);
  sth2.set_timestamp(sth.timestamp() - 1000);
  EXPECT_EQ(Database::OK, this->db()->WriteTreeHead(sth));
  EXPECT_EQ(Database::OK, this->db()->WriteTreeHead(sth2));

  Database *db2 = this->test_db_.SecondDB();

  EXPECT_EQ(Database::LOOKUP_OK,
            db2->LookupCertificateByHash(
                logged_cert.certificate_sha256_hash(), &lookup_cert));
  EXPECT_EQ(42U, lookup_cert.sequence_number());

  lookup_cert.clear_sequence_number();
  TestSigner::TestEqualLoggedCerts(logged_cert, lookup_cert);

  EXPECT_EQ(Database::LOOKUP_OK,
            db2->LookupCertificateByHash(
                logged_cert2.certificate_sha256_hash(), &lookup_cert2));
  TestSigner::TestEqualLoggedCerts(logged_cert2, lookup_cert2);

  EXPECT_EQ(Database::LOOKUP_OK, db2->LatestTreeHead(&lookup_sth));
  TestSigner::TestEqualTreeHeads(sth, lookup_sth);

  std::set<string> pending_hashes;
  pending_hashes.insert(logged_cert2.certificate_sha256_hash());

  EXPECT_EQ(pending_hashes, db2->PendingHashes());

  delete db2;
}

TYPED_TEST(DBTest, ResumeEmpty) {
  Database *db2 = this->test_db_.SecondDB();

  LoggedCertificate lookup_cert;
  EXPECT_EQ(Database::NOT_FOUND,
            db2->LookupCertificateByIndex(0, &lookup_cert));

  SignedTreeHead lookup_sth;
  EXPECT_EQ(Database::NOT_FOUND, db2->LatestTreeHead(&lookup_sth));

  EXPECT_TRUE(db2->PendingHashes().empty());

  delete db2;
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
  return RUN_ALL_TESTS();
}
