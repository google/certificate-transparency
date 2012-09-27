/* -*- indent-tabs-mode: nil -*- */

#include <gtest/gtest.h>
#include <iostream>
#include <set>
#include <stdint.h>
#include <string>
#include <sys/stat.h>

#include "database.h"
#include "file_db.h"
#include "file_storage.h"
#include "sqlite_db.h"
#include "types.h"
#include "util.h"

namespace {

using ct::CertificateEntry;
using ct::DigitallySigned;
using ct::LoggedCertificate;
using ct::SignedTreeHead;

const unsigned kCertStorageDepth = 3;
const unsigned kTreeStorageDepth = 8;

// A slightly shorter notation for constructing binary blobs from test vectors.
bstring B(const char *hexstring) {
  return util::BinaryString(hexstring);
}

// The reverse.
std::string H(const bstring &byte_string) {
  return util::HexString(byte_string);
}

const char kDefaultHash[] =
    "18041bd4665083001fba8c5411d2d748e8abbfdcdfd9218cb02b68a78e7d4c23";

const char kAlternativeHash[] =
    "3bfb960453ebaebf33727da7a1f4db38acc051d381b6da20d6d4e88f0eabfd7a";

const char kDefaultSignature[] =
    "3046022100ee89fb556fd72264098e8c80da9141c2aa2a788587bcc73d235ff7fd42dd5a11"
    "022100a3df4dd9c6cc6374ec1a7ba06d3a3c791e542287819fe1a15ca134d9cbb8bb74";

const char kDefaultDerCert[] =
    "308202ca30820233a003020102020102300d06092a864886f70d01010505003055310b3009"
    "06035504061302474231243022060355040a131b4365727469666963617465205472616e73"
    "706172656e6379204341310e300c0603550408130557616c65733110300e06035504071307"
    "4572772057656e301e170d3132303630313030303030305a170d3232303630313030303030"
    "305a3052310b30090603550406130247423121301f060355040a1318436572746966696361"
    "7465205472616e73706172656e6379310e300c0603550408130557616c65733110300e0603"
    "55040713074572772057656e30819f300d06092a864886f70d010101050003818d00308189"
    "02818100b8742267898b99ba6bfd6e6f7ada8e54337f58feb7227c46248437ba5f89b007cb"
    "e1ecb4545b38ed23fddbf6b9742cafb638157f68184776a1b38ab39318ddd734489b4d7501"
    "17cd83a220a7b52f295d1e18571469a581c23c68c57d973761d9787a091fb5864936b16653"
    "5e21b427e3c6d690b2e91a87f36b7ec26f59ce53b50203010001a381ac3081a9301d060355"
    "1d0e041604141184e1187c87956dffc31dd0521ff564efbeae8d307d0603551d2304763074"
    "8014a3b8d89ba2690dfb48bbbf87c1039ddce56256c6a159a4573055310b30090603550406"
    "1302474231243022060355040a131b4365727469666963617465205472616e73706172656e"
    "6379204341310e300c0603550408130557616c65733110300e060355040713074572772057"
    "656e82010030090603551d1304023000300d06092a864886f70d010105050003818100292e"
    "cf6e46c7a0bcd69051739277710385363341c0a9049637279707ae23cc5128a4bdea0d480e"
    "d0206b39e3a77a2b0c49b0271f4140ab75c1de57aba498e09459b479cf92a4d5d5dd5cbe3f"
    "0a11e25f04078df88fc388b61b867a8de46216c0e17c31fc7d8003ecc37be22292f84242ab"
    "87fb08bd4dfa3c1b9ce4d3ee6667da";

template <class T> class DBTest : public ::testing::Test {
 protected:
  DBTest() :
      db_(NULL),
      logged_cert_(),
      tree_head_() {
    // Some time in September 2012.
    logged_cert_.mutable_sct()->set_timestamp(1348589665525LL);
    logged_cert_.mutable_sct()->mutable_entry()->set_type(
        CertificateEntry::X509_ENTRY);
    logged_cert_.mutable_sct()->mutable_entry()->set_leaf_certificate(
        B(kDefaultDerCert));
    logged_cert_.mutable_sct()->mutable_signature()->set_hash_algorithm(
        DigitallySigned::SHA256);
    logged_cert_.mutable_sct()->mutable_signature()->set_sig_algorithm(
        DigitallySigned::ECDSA);
    logged_cert_.mutable_sct()->mutable_signature()->set_signature(
        B(kDefaultSignature));
    // FIXME(ekasper): don't assume SHA256 in test vectors
    // (despite the field name).
    logged_cert_.set_certificate_sha256_hash(B(kDefaultHash));

    tree_head_.set_timestamp(1348589665525LL);
    tree_head_.set_tree_size(42);
    tree_head_.set_root_hash(B(kDefaultHash));
    tree_head_.mutable_signature()->set_hash_algorithm(
        DigitallySigned::SHA256);
    tree_head_.mutable_signature()->set_sig_algorithm(
        DigitallySigned::ECDSA);
    tree_head_.mutable_signature()->set_signature(B(kDefaultSignature));
  }

  void SetUp();
  void TearDown();
  // provide a second reference to the same test database
  Database *SecondDB();

  const LoggedCertificate &DefaultLoggedCert() const {
    return logged_cert_;
  }

  const SignedTreeHead &DefaultTreeHead() const {
    return tree_head_;
  }

  const uint64_t DefaultTimestamp() const {
    return logged_cert_.sct().timestamp();
  }

  const bstring DefaultHash() const {
    return logged_cert_.certificate_sha256_hash();
  }

  const bstring AlternativeHash() const {
    return B(kAlternativeHash);
  }

  const uint64_t DefaultTreeSize() const {
    return tree_head_.tree_size();
  }

  ~DBTest() {
    if (db_ != NULL)
      delete db_;
  }

  Database *db_;
  std::string file_base_;
  LoggedCertificate logged_cert_;
  SignedTreeHead tree_head_;
};

template <> void DBTest<FileDB>::SetUp() {
  file_base_ = util::CreateTemporaryDirectory("/tmp/ctlogXXXXXX");
  ASSERT_EQ("/tmp/ctlog", file_base_.substr(0, 10));
  ASSERT_EQ(16U, file_base_.length());
  std::string certs_dir = file_base_ + "/certs";
  std::string tree_dir = file_base_ + "/tree";
  int ret = mkdir(certs_dir.c_str(), 0700);
  ASSERT_EQ(ret, 0);
  ret = mkdir(tree_dir.c_str(), 0700);
  ASSERT_EQ(ret, 0);

  db_ = new FileDB(new FileStorage(certs_dir, kCertStorageDepth),
                   new FileStorage(tree_dir, kTreeStorageDepth));
}

template <> void DBTest<FileDB>::TearDown() {
  // Check again that it is safe to empty file_base_.
  ASSERT_EQ("/tmp/ctlog", file_base_.substr(0, 10));
  ASSERT_EQ(16U, file_base_.length());
  std::string command = "rm -r " + file_base_;
  int ret = system(command.c_str());
  if (ret != 0)
    std::cout << "Failed to delete temporary directory in "
              << file_base_ << std::endl;
}

template <> Database *DBTest<FileDB>::SecondDB() {
  std::string certs_dir = this->file_base_ + "/certs";
  std::string tree_dir = this->file_base_ + "/tree";
  return new FileDB(new FileStorage(certs_dir, kCertStorageDepth),
                    new FileStorage(tree_dir, kTreeStorageDepth));
}

template <> void DBTest<SQLiteDB>::SetUp() {
  file_base_ = util::CreateTemporaryDirectory("/tmp/ctlogXXXXXX");
  ASSERT_EQ("/tmp/ctlog", file_base_.substr(0, 10));
  ASSERT_EQ(16U, file_base_.length());
  db_ = new SQLiteDB(file_base_ + "/ct");
}

template <> void DBTest<SQLiteDB>::TearDown() {
  // Check again that it is safe to empty file_base_.
  ASSERT_EQ("/tmp/ctlog", file_base_.substr(0, 10));
  ASSERT_EQ(16U, file_base_.length());
  std::string command = "rm -r " + file_base_;
  int ret = system(command.c_str());
  if (ret != 0)
    std::cout << "Failed to delete temporary directory in "
              << file_base_ << std::endl;
}

template <> Database *DBTest<SQLiteDB>::SecondDB() {
  return new SQLiteDB(file_base_ + "/ct");
}

typedef testing::Types<FileDB, SQLiteDB> Databases;

TYPED_TEST_CASE(DBTest, Databases);

void CompareDS(const DigitallySigned &ds, const DigitallySigned &ds2) {
  EXPECT_EQ(ds.hash_algorithm(), ds2.hash_algorithm());
  EXPECT_EQ(ds.sig_algorithm(), ds2.sig_algorithm());
  EXPECT_EQ(H(ds.signature()), H(ds2.signature()));
}

void CompareLoggedCerts(const LoggedCertificate &c1,
                        const LoggedCertificate &c2) {
  EXPECT_EQ(c1.sct().timestamp(), c2.sct().timestamp());
  EXPECT_EQ(c1.sct().entry().type(), c2.sct().entry().type());
  EXPECT_EQ(H(c1.sct().entry().leaf_certificate()),
            H(c2.sct().entry().leaf_certificate()));
  // Skip intermediates for now.
  CompareDS(c1.sct().signature(), c2.sct().signature());

  EXPECT_EQ(H(c1.certificate_sha256_hash()),
            H(c2.certificate_sha256_hash()));
  EXPECT_EQ(c1.has_sequence_number(), c2.has_sequence_number());
  // Defaults to 0 if not set.
  EXPECT_EQ(c1.sequence_number(), c2.sequence_number());
}

void CompareTreeHeads(const SignedTreeHead &sth1,
                      const SignedTreeHead &sth2) {
  EXPECT_EQ(sth1.tree_size(), sth2.tree_size());
  EXPECT_EQ(sth1.timestamp(), sth2.timestamp());
  EXPECT_EQ(H(sth1.root_hash()), H(sth2.root_hash()));
  CompareDS(sth1.signature(), sth2.signature());
}

TYPED_TEST(DBTest, CreatePending) {
  LoggedCertificate lookup_cert;

  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(
                this->DefaultLoggedCert()));

  EXPECT_EQ(Database::LOOKUP_OK,
            this->db_->LookupCertificateByHash(this->DefaultHash(),
                                               &lookup_cert));
  CompareLoggedCerts(this->DefaultLoggedCert(), lookup_cert);

  EXPECT_EQ(Database::NOT_FOUND,
            this->db_->LookupCertificateByHash(this->AlternativeHash(),
                                               &lookup_cert));
}

TYPED_TEST(DBTest, GetPending) {
  LoggedCertificate logged_cert;
  logged_cert.CopyFrom(this->DefaultLoggedCert());
  logged_cert.set_certificate_sha256_hash(this->AlternativeHash());

  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(
                this->DefaultLoggedCert()));
  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(logged_cert));

  std::set<bstring> hashes;
  hashes.insert(this->DefaultHash());
  hashes.insert(this->AlternativeHash());

  std::set<bstring> pending_hashes = this->db_->PendingHashes();
  EXPECT_EQ(hashes, pending_hashes);
}

TYPED_TEST(DBTest, CreatePendingDuplicate) {
  LoggedCertificate logged_cert, lookup_cert;
  logged_cert.CopyFrom(this->DefaultLoggedCert());
  // Change the timestamp.
  logged_cert.mutable_sct()->set_timestamp(this->DefaultTimestamp() + 1000);

  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(
                this->DefaultLoggedCert()));
  EXPECT_EQ(Database::DUPLICATE_CERTIFICATE_HASH,
            this->db_->CreatePendingCertificateEntry(logged_cert));

  EXPECT_EQ(Database::LOOKUP_OK,
            this->db_->LookupCertificateByHash(this->DefaultHash(),
                                               &lookup_cert));
  // Check that we get the original entry back.
  CompareLoggedCerts(this->DefaultLoggedCert(), lookup_cert);
}

TYPED_TEST(DBTest, AssignSequenceNumber) {
  LoggedCertificate lookup_cert;

  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(
                this->DefaultLoggedCert()));
  EXPECT_EQ(Database::OK,
            this->db_->AssignCertificateSequenceNumber(this->DefaultHash(),
                                                       42));

  EXPECT_EQ(Database::LOOKUP_OK,
            this->db_->LookupCertificateByHash(this->DefaultHash(),
                                               &lookup_cert));
  EXPECT_EQ(42U, lookup_cert.sequence_number());

  lookup_cert.clear_sequence_number();
  CompareLoggedCerts(this->DefaultLoggedCert(), lookup_cert);
}

TYPED_TEST(DBTest, AssignSequenceNumberNotPending) {
  EXPECT_EQ(Database::ENTRY_NOT_FOUND,
            this->db_->AssignCertificateSequenceNumber(this->DefaultHash(), 0));

  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(
                this->DefaultLoggedCert()));
  EXPECT_EQ(Database::OK,
            this->db_->AssignCertificateSequenceNumber(this->DefaultHash(),
                                                       42));

  EXPECT_EQ(Database::ENTRY_ALREADY_LOGGED,
            this->db_->AssignCertificateSequenceNumber(this->DefaultHash(),
                                                       42));
}

TYPED_TEST(DBTest, AssignSequenceNumberTwice) {
  LoggedCertificate logged_cert;
  logged_cert.CopyFrom(this->DefaultLoggedCert());
  logged_cert.set_certificate_sha256_hash(this->AlternativeHash());

  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(
                this->DefaultLoggedCert()));
  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(logged_cert));
  EXPECT_EQ(Database::OK,
            this->db_->AssignCertificateSequenceNumber(
                this->DefaultHash(), 42));
  EXPECT_EQ(Database::SEQUENCE_NUMBER_ALREADY_IN_USE,
            this->db_->AssignCertificateSequenceNumber(this->AlternativeHash(),
                                                       42));
}

TYPED_TEST(DBTest, LookupBySequenceNumber) {
  LoggedCertificate logged_cert, lookup_cert0, lookup_cert1;
  logged_cert.CopyFrom(this->DefaultLoggedCert());
  logged_cert.set_certificate_sha256_hash(this->AlternativeHash());
  logged_cert.mutable_sct()->set_timestamp(this->DefaultTimestamp() + 1000);

  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(
                this->DefaultLoggedCert()));
  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(logged_cert));
  EXPECT_EQ(Database::OK,
            this->db_->AssignCertificateSequenceNumber(
                this->DefaultHash(), 42));
  EXPECT_EQ(Database::OK,
            this->db_->AssignCertificateSequenceNumber(this->AlternativeHash(),
                                                       22));

  EXPECT_EQ(Database::NOT_FOUND,
            this->db_->LookupCertificateByIndex(23, &lookup_cert0));

  EXPECT_EQ(Database::LOOKUP_OK,
            this->db_->LookupCertificateByIndex(42, &lookup_cert0));
  EXPECT_EQ(42U, lookup_cert0.sequence_number());

  lookup_cert0.clear_sequence_number();
  CompareLoggedCerts(this->DefaultLoggedCert(), lookup_cert0);

  EXPECT_EQ(Database::LOOKUP_OK,
            this->db_->LookupCertificateByIndex(22, &lookup_cert1));
  EXPECT_EQ(22U, lookup_cert1.sequence_number());
  EXPECT_EQ(this->DefaultTimestamp() + 1000, lookup_cert1.sct().timestamp());
}

TYPED_TEST(DBTest, WriteTreeHead) {
  SignedTreeHead lookup_sth;

  EXPECT_EQ(Database::NOT_FOUND, this->db_->LatestTreeHead(&lookup_sth));

  EXPECT_EQ(Database::OK, this->db_->WriteTreeHead(this->DefaultTreeHead()));

  EXPECT_EQ(Database::LOOKUP_OK, this->db_->LatestTreeHead(&lookup_sth));
  CompareTreeHeads(this->DefaultTreeHead(), lookup_sth);
}

TYPED_TEST(DBTest, WriteTreeHeadDuplicateTimestamp) {
  SignedTreeHead sth, lookup_sth;

  EXPECT_EQ(Database::OK, this->db_->WriteTreeHead(this->DefaultTreeHead()));

  sth.CopyFrom(this->DefaultTreeHead());
  sth.set_tree_size(this->DefaultTreeSize() + 1);
  EXPECT_EQ(Database::DUPLICATE_TREE_HEAD_TIMESTAMP,
            this->db_->WriteTreeHead(sth));

  EXPECT_EQ(Database::LOOKUP_OK, this->db_->LatestTreeHead(&lookup_sth));
  CompareTreeHeads(this->DefaultTreeHead(), lookup_sth);
}

TYPED_TEST(DBTest, WriteTreeHeadNewerTimestamp) {
  SignedTreeHead sth, lookup_sth;

  EXPECT_EQ(Database::OK, this->db_->WriteTreeHead(this->DefaultTreeHead()));

  sth.CopyFrom(this->DefaultTreeHead());
  sth.set_timestamp(this->DefaultTimestamp() + 1000);
  EXPECT_EQ(Database::OK, this->db_->WriteTreeHead(sth));

  EXPECT_EQ(Database::LOOKUP_OK, this->db_->LatestTreeHead(&lookup_sth));
  CompareTreeHeads(sth, lookup_sth);
}

TYPED_TEST(DBTest, WriteTreeHeadOlderTimestamp) {
  SignedTreeHead sth, lookup_sth;

  EXPECT_EQ(Database::OK, this->db_->WriteTreeHead(this->DefaultTreeHead()));

  sth.CopyFrom(this->DefaultTreeHead());
  sth.set_timestamp(this->DefaultTimestamp() - 1000);
  EXPECT_EQ(Database::OK, this->db_->WriteTreeHead(sth));

  EXPECT_EQ(Database::LOOKUP_OK, this->db_->LatestTreeHead(&lookup_sth));
  CompareTreeHeads(this->DefaultTreeHead(), lookup_sth);
}

TYPED_TEST(DBTest, Resume) {
  LoggedCertificate logged_cert, lookup_cert0, lookup_cert1;
  logged_cert.CopyFrom(this->DefaultLoggedCert());
  logged_cert.set_certificate_sha256_hash(this->AlternativeHash());
  logged_cert.mutable_sct()->set_timestamp(this->DefaultTimestamp() + 1000);

  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(
                this->DefaultLoggedCert()));
  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(logged_cert));
  EXPECT_EQ(Database::OK,
            this->db_->AssignCertificateSequenceNumber(
                this->DefaultHash(), 42));

  SignedTreeHead sth, lookup_sth;
  sth.CopyFrom(this->DefaultTreeHead());
  sth.set_timestamp(this->DefaultTimestamp() - 1000);
  EXPECT_EQ(Database::OK, this->db_->WriteTreeHead(this->DefaultTreeHead()));
  EXPECT_EQ(Database::OK, this->db_->WriteTreeHead(sth));

  Database *db2 = this->SecondDB();

  EXPECT_EQ(Database::LOOKUP_OK,
            db2->LookupCertificateByHash(this->DefaultHash(), &lookup_cert0));
  EXPECT_EQ(42U, lookup_cert0.sequence_number());

  lookup_cert0.clear_sequence_number();
  CompareLoggedCerts(this->DefaultLoggedCert(), lookup_cert0);

  EXPECT_EQ(Database::LOOKUP_OK,
            db2->LookupCertificateByHash(this->AlternativeHash(),
                                         &lookup_cert1));
  CompareLoggedCerts(logged_cert, lookup_cert1);

  EXPECT_EQ(Database::LOOKUP_OK, db2->LatestTreeHead(&lookup_sth));
  CompareTreeHeads(this->DefaultTreeHead(), lookup_sth);

  std::set<bstring> pending_hashes;
  pending_hashes.insert(this->AlternativeHash());

  EXPECT_EQ(pending_hashes, db2->PendingHashes());

  delete db2;
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
