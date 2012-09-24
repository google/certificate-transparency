/* -*- indent-tabs-mode: nil -*- */

#include <gtest/gtest.h>
#include <iostream>
#include <set>
#include <stdint.h>
#include <string>

#include "certificate_db.h"
#include "database.h"
#include "file_storage.h"
#include "types.h"
#include "util.h"

namespace {

using ct::SignedCertificateTimestamp;

const unsigned kStorageDepth = 3;

template <class T> class DBTest : public ::testing::Test {
 protected:
  DBTest() :
      db_(NULL) { }

  void SetUp();
  void TearDown();
  // provide a second reference to the same test database
  Database *SecondDB();

  ~DBTest() {
    if (db_ != NULL)
      delete db_;
  }

  Database *db_;
  std::string file_base_;
};

template <> void DBTest<CertificateDB>::SetUp() {
  file_base_ = util::CreateTemporaryDirectory("/tmp/ctlogXXXXXX");
  ASSERT_EQ("/tmp/ctlog", file_base_.substr(0, 10));
  ASSERT_EQ(16U, file_base_.length());
  db_ = new CertificateDB(new FileStorage(file_base_, kStorageDepth));
}

template <> void DBTest<CertificateDB>::TearDown() {
  // Check again that it is safe to empty file_base_.
  ASSERT_EQ("/tmp/ctlog", file_base_.substr(0, 10));
  ASSERT_EQ(16U, file_base_.length());
  std::string command = "rm -r " + file_base_;
  int ret = system(command.c_str());
  if (ret != 0)
    std::cout << "Failed to delete temporary directory in "
              << file_base_ << std::endl;
}

template <> Database *DBTest<CertificateDB>::SecondDB() {
  return new CertificateDB(new FileStorage(this->file_base_, kStorageDepth));
}

TYPED_TEST_CASE(DBTest, CertificateDB);

TYPED_TEST(DBTest, CreatePending) {
  bstring key("1234xyzw", 8);

  SignedCertificateTimestamp sct, lookup_sct;
  // Set some fields to double-check we get the same data back.
  sct.set_timestamp(1234);

  EXPECT_EQ(Database::OK, this->db_->CreatePendingCertificateEntry(key, sct));

  EXPECT_EQ(Database::PENDING,
            this->db_->LookupCertificateEntry(key, &lookup_sct));
  EXPECT_EQ(1234U, lookup_sct.timestamp());
}

TYPED_TEST(DBTest, GetPending) {
  bstring key0("1234xyzw", 8);
  bstring key1("1245abcd", 8);

  SignedCertificateTimestamp sct0, sct1;
  sct0.set_timestamp(1234);
  sct1.set_timestamp(1235);

  EXPECT_EQ(Database::OK, this->db_->CreatePendingCertificateEntry(key0, sct0));
  EXPECT_EQ(Database::OK, this->db_->CreatePendingCertificateEntry(key1, sct1));

  std::set<bstring> keys;
  keys.insert(key0);
  keys.insert(key1);

  std::set<bstring> pending_keys = this->db_->PendingKeys();
  EXPECT_EQ(keys, pending_keys);
}

TYPED_TEST(DBTest, CreatePendingDuplicate) {
  bstring key("1234xyzw", 8);

  SignedCertificateTimestamp sct0, sct1;
  sct0.set_timestamp(1234);
  sct1.set_timestamp(1235);

  EXPECT_EQ(Database::OK, this->db_->CreatePendingCertificateEntry(key, sct0));
  EXPECT_EQ(Database::ENTRY_ALREADY_PENDING,
            this->db_->CreatePendingCertificateEntry(key, sct1));

  EXPECT_EQ(Database::PENDING, this->db_->LookupCertificateEntry(key, &sct1));
  EXPECT_EQ(1234U, sct1.timestamp());
}

TYPED_TEST(DBTest, AssignSequenceNumber) {
  bstring key("1234xyzw", 8);

  SignedCertificateTimestamp sct, lookup_sct;
  // Set some fields to double-check we get the same data back.
  sct.set_timestamp(1234);

  EXPECT_EQ(Database::OK, this->db_->CreatePendingCertificateEntry(key, sct));
  EXPECT_EQ(Database::OK, this->db_->AssignCertificateSequenceNumber(key, 42));

  uint64_t sequence_number = 0;
  EXPECT_EQ(Database::LOGGED,
            this->db_->LookupCertificateEntry(key, &sequence_number,
                                              &lookup_sct));
  EXPECT_EQ(1234U, lookup_sct.timestamp());
  EXPECT_EQ(42U, sequence_number);
}

TYPED_TEST(DBTest, AssignSequenceNumberNotPending) {
  bstring key("1234xyzw", 8);

  EXPECT_EQ(Database::ENTRY_NOT_FOUND,
            this->db_->AssignCertificateSequenceNumber(key, 0));

  SignedCertificateTimestamp sct;
  sct.set_timestamp(1234);
  EXPECT_EQ(Database::OK, this->db_->CreatePendingCertificateEntry(key, sct));
  EXPECT_EQ(Database::OK, this->db_->AssignCertificateSequenceNumber(key, 42));

  EXPECT_EQ(Database::ENTRY_ALREADY_LOGGED,
            this->db_->AssignCertificateSequenceNumber(key, 42));
}

TYPED_TEST(DBTest, AssignSequenceNumberTwice) {
  bstring key0("1234xyzw", 8);
  bstring key1("1245abcd", 8);

  SignedCertificateTimestamp sct0, sct1;
  sct0.set_timestamp(1234);
  sct1.set_timestamp(1235);

  EXPECT_EQ(Database::OK, this->db_->CreatePendingCertificateEntry(key0, sct0));
  EXPECT_EQ(Database::OK, this->db_->CreatePendingCertificateEntry(key1, sct1));
  EXPECT_EQ(Database::OK, this->db_->AssignCertificateSequenceNumber(key0, 42));
  EXPECT_EQ(Database::SEQUENCE_NUMBER_ALREADY_IN_USE,
            this->db_->AssignCertificateSequenceNumber(key1, 42));
}

TYPED_TEST(DBTest, LookupBySequenceNumber) {
  bstring key0("1234xyzw", 8);
  bstring key1("1245abcd", 8);

  SignedCertificateTimestamp sct0, sct1, lookup_sct0, lookup_sct1;
  sct0.set_timestamp(1234);
  sct1.set_timestamp(1235);

  EXPECT_EQ(Database::OK, this->db_->CreatePendingCertificateEntry(key0, sct0));
  EXPECT_EQ(Database::OK, this->db_->CreatePendingCertificateEntry(key1, sct1));
  EXPECT_EQ(Database::OK, this->db_->AssignCertificateSequenceNumber(key0, 42));
  EXPECT_EQ(Database::OK, this->db_->AssignCertificateSequenceNumber(key1, 22));

  EXPECT_EQ(Database::LOGGED,
            this->db_->LookupCertificateEntry(42, &lookup_sct0));
  EXPECT_EQ(1234U, lookup_sct0.timestamp());

  EXPECT_EQ(Database::LOGGED,
            this->db_->LookupCertificateEntry(22, &lookup_sct1));
  EXPECT_EQ(1235U, lookup_sct1.timestamp());
}

TYPED_TEST(DBTest, Resume) {
  bstring key0("1234xyzw", 8);
  bstring key1("1245abcd", 8);

  SignedCertificateTimestamp sct0, sct1, lookup_sct0, lookup_sct1;
  sct0.set_timestamp(1234);
  sct1.set_timestamp(1235);

  EXPECT_EQ(Database::OK, this->db_->CreatePendingCertificateEntry(key0, sct0));
  EXPECT_EQ(Database::OK, this->db_->CreatePendingCertificateEntry(key1, sct1));
  EXPECT_EQ(Database::OK, this->db_->AssignCertificateSequenceNumber(key0, 42));

  Database *db2 = this->SecondDB();

  uint64_t sequence_number = 0;
  EXPECT_EQ(Database::LOGGED,
            db2->LookupCertificateEntry(key0, &sequence_number, &lookup_sct0));
  EXPECT_EQ(1234U, lookup_sct0.timestamp());
  EXPECT_EQ(42U, sequence_number);

  EXPECT_EQ(Database::PENDING, db2->LookupCertificateEntry(key1, &lookup_sct1));
  EXPECT_EQ(1235U, lookup_sct1.timestamp());

  std::set<bstring> pending_keys;
  pending_keys.insert(key1);

  EXPECT_EQ(pending_keys, db2->PendingKeys());

  delete db2;
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
