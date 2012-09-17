#include <gtest/gtest.h>
#include <iostream>
#include <set>
#include <stdint.h>
#include <string>

#include "certificate_db.h"
#include "file_db.h"
#include "types.h"
#include "util.h"

namespace {

using ct::SignedCertificateTimestamp;

const unsigned kStorageDepth = 3;

class CertificateDBTest : public ::testing::Test {
 protected:
  CertificateDBTest() :
      cert_db_(NULL) { }

  void SetUp() {
    file_base_ = util::CreateTemporaryDirectory("/tmp/ctlogXXXXXX");
    ASSERT_EQ("/tmp/ctlog", file_base_.substr(0, 10));
    ASSERT_EQ(16U, file_base_.length());
    cert_db_ = new CertificateDB(new FileDB(file_base_, kStorageDepth));
  }

  void TearDown() {
    // Check again that it is safe to empty file_base_.
    ASSERT_EQ("/tmp/ctlog", file_base_.substr(0, 10));
    ASSERT_EQ(16U, file_base_.length());
    std::string command = "rm -r " + file_base_;
    int ret = system(command.c_str());
    if (ret != 0)
      std::cout << "Failed to delete temporary directory in "
                << file_base_ << std::endl;
  }

  ~CertificateDBTest() {
    if (cert_db_ != NULL)
      delete cert_db_;
  }

  CertificateDB *cert_db_;
  std::string file_base_;
};

TEST_F(CertificateDBTest, CreatePending) {
  bstring key("1234xyzw", 8);

  SignedCertificateTimestamp sct, lookup_sct;
  // Set some fields to double-check we get the same data back.
  sct.set_timestamp(1234);

  EXPECT_EQ(CertificateDB::OK,
            cert_db_->CreatePendingCertificateEntry(key, sct));

  EXPECT_EQ(CertificateDB::PENDING,
            cert_db_->LookupCertificateEntry(key, &lookup_sct));
  EXPECT_EQ(1234U, lookup_sct.timestamp());
}

TEST_F(CertificateDBTest, GetPending) {
  bstring key0("1234xyzw", 8);
  bstring key1("1245abcd", 8);

  SignedCertificateTimestamp sct0, sct1;
  sct0.set_timestamp(1234);
  sct1.set_timestamp(1235);

  EXPECT_EQ(CertificateDB::OK,
            cert_db_->CreatePendingCertificateEntry(key0, sct0));
  EXPECT_EQ(CertificateDB::OK,
            cert_db_->CreatePendingCertificateEntry(key1, sct1));

  std::set<bstring> keys;
  keys.insert(key0);
  keys.insert(key1);

  std::set<bstring> pending_keys = cert_db_->PendingKeys();
  EXPECT_EQ(keys, pending_keys);
}

TEST_F(CertificateDBTest, CreatePendingDuplicate) {
  bstring key("1234xyzw", 8);

  SignedCertificateTimestamp sct0, sct1;
  sct0.set_timestamp(1234);
  sct1.set_timestamp(1235);

  EXPECT_EQ(CertificateDB::OK,
            cert_db_->CreatePendingCertificateEntry(key, sct0));
  EXPECT_EQ(CertificateDB::ENTRY_ALREADY_PENDING,
            cert_db_->CreatePendingCertificateEntry(key, sct1));

  EXPECT_EQ(CertificateDB::PENDING,
            cert_db_->LookupCertificateEntry(key, &sct1));
  EXPECT_EQ(1234U, sct1.timestamp());
}

TEST_F(CertificateDBTest, AssignSequenceNumber) {
  bstring key("1234xyzw", 8);

  SignedCertificateTimestamp sct, lookup_sct;
  // Set some fields to double-check we get the same data back.
  sct.set_timestamp(1234);

  EXPECT_EQ(CertificateDB::OK,
            cert_db_->CreatePendingCertificateEntry(key, sct));
  EXPECT_EQ(CertificateDB::OK,
            cert_db_->AssignCertificateSequenceNumber(key, 42));

  uint64_t sequence_number = 0;
  EXPECT_EQ(CertificateDB::LOGGED,
            cert_db_->LookupCertificateEntry(key, &sequence_number,
                                             &lookup_sct));
  EXPECT_EQ(1234U, lookup_sct.timestamp());
  EXPECT_EQ(42U, sequence_number);
}

TEST_F(CertificateDBTest, AssignSequenceNumberNotPending) {
  bstring key("1234xyzw", 8);

  EXPECT_EQ(CertificateDB::ENTRY_NOT_FOUND,
            cert_db_->AssignCertificateSequenceNumber(key, 0));

  SignedCertificateTimestamp sct;
  sct.set_timestamp(1234);
  EXPECT_EQ(CertificateDB::OK,
            cert_db_->CreatePendingCertificateEntry(key, sct));
  EXPECT_EQ(CertificateDB::OK,
            cert_db_->AssignCertificateSequenceNumber(key, 42));

  EXPECT_EQ(CertificateDB::ENTRY_ALREADY_LOGGED,
            cert_db_->AssignCertificateSequenceNumber(key, 42));
}

TEST_F(CertificateDBTest, AssignSequenceNumberTwice) {
  bstring key0("1234xyzw", 8);
  bstring key1("1245abcd", 8);

  SignedCertificateTimestamp sct0, sct1;
  sct0.set_timestamp(1234);
  sct1.set_timestamp(1235);

  EXPECT_EQ(CertificateDB::OK,
            cert_db_->CreatePendingCertificateEntry(key0, sct0));
  EXPECT_EQ(CertificateDB::OK,
            cert_db_->CreatePendingCertificateEntry(key1, sct1));
  EXPECT_EQ(CertificateDB::OK,
            cert_db_->AssignCertificateSequenceNumber(key0, 42));
  EXPECT_EQ(CertificateDB::SEQUENCE_NUMBER_ALREADY_IN_USE,
            cert_db_->AssignCertificateSequenceNumber(key1, 42));
}

TEST_F(CertificateDBTest, LookupBySequenceNumber) {
  bstring key0("1234xyzw", 8);
  bstring key1("1245abcd", 8);

  SignedCertificateTimestamp sct0, sct1, lookup_sct0, lookup_sct1;
  sct0.set_timestamp(1234);
  sct1.set_timestamp(1235);

  EXPECT_EQ(CertificateDB::OK,
            cert_db_->CreatePendingCertificateEntry(key0, sct0));
  EXPECT_EQ(CertificateDB::OK,
            cert_db_->CreatePendingCertificateEntry(key1, sct1));
  EXPECT_EQ(CertificateDB::OK,
            cert_db_->AssignCertificateSequenceNumber(key0, 42));
  EXPECT_EQ(CertificateDB::OK,
            cert_db_->AssignCertificateSequenceNumber(key1, 22));

  EXPECT_EQ(CertificateDB::LOGGED,
            cert_db_->LookupCertificateEntry(42, &lookup_sct0));
  EXPECT_EQ(1234U, lookup_sct0.timestamp());

  EXPECT_EQ(CertificateDB::LOGGED,
            cert_db_->LookupCertificateEntry(22, &lookup_sct1));
  EXPECT_EQ(1235U, lookup_sct1.timestamp());
}

TEST_F(CertificateDBTest, Resume) {
  bstring key0("1234xyzw", 8);
  bstring key1("1245abcd", 8);

  SignedCertificateTimestamp sct0, sct1, lookup_sct0, lookup_sct1;
  sct0.set_timestamp(1234);
  sct1.set_timestamp(1235);

  EXPECT_EQ(CertificateDB::OK,
            cert_db_->CreatePendingCertificateEntry(key0, sct0));
  EXPECT_EQ(CertificateDB::OK,
            cert_db_->CreatePendingCertificateEntry(key1, sct1));
  EXPECT_EQ(CertificateDB::OK,
            cert_db_->AssignCertificateSequenceNumber(key0, 42));

  CertificateDB db2(new FileDB(file_base_, kStorageDepth));

  uint64_t sequence_number = 0;
  EXPECT_EQ(CertificateDB::LOGGED,
            db2.LookupCertificateEntry(key0, &sequence_number,
                                       &lookup_sct0));
  EXPECT_EQ(1234U, lookup_sct0.timestamp());
  EXPECT_EQ(42U, sequence_number);

  EXPECT_EQ(CertificateDB::PENDING,
            db2.LookupCertificateEntry(key1, &lookup_sct1));
  EXPECT_EQ(1235U, lookup_sct1.timestamp());

  std::set<bstring> pending_keys;
  pending_keys.insert(key1);

  EXPECT_EQ(pending_keys, db2.PendingKeys());
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
