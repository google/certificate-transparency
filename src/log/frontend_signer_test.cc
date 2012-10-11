/* -*- indent-tabs-mode: nil -*- */
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <string>

#include "ct.pb.h"
#include "file_db.h"
#include "frontend_signer.h"
#include "log_verifier.h"
#include "merkle_verifier.h"
#include "serial_hasher.h"
#include "sqlite_db.h"
#include "test_db.h"
#include "test_signer.h"
#include "util.h"

namespace {

using ct::CertificateEntry;
using ct::LoggedCertificate;
using ct::SignedCertificateTimestamp;
using std::string;

// A slightly shorter notation for constructing hex strings from binary blobs.
string H(const string &byte_string) {
  return util::HexString(byte_string);
}

template <class T> class FrontendSignerTest : public ::testing::Test {
 protected:
  FrontendSignerTest()
      : test_db_(),
        test_signer_(),
        verifier_(new LogVerifier(TestSigner::DefaultVerifier(),
                                  new MerkleVerifier(new Sha256Hasher()))),
        frontend_(new FrontendSigner(test_db_.db(),
                                     TestSigner::DefaultSigner())) {}

  ~FrontendSignerTest() {
    delete verifier_;
    delete frontend_;
  }

  T *db() const { return test_db_.db(); }

  TestDB<T> test_db_;
  TestSigner test_signer_;
  LogVerifier *verifier_;
  FrontendSigner *frontend_;
};

void CompareEntries(const CertificateEntry &entry0,
                    const CertificateEntry &entry1) {
  EXPECT_EQ(entry0.type(), entry1.type());
  EXPECT_EQ(H(entry0.leaf_certificate()), H(entry1.leaf_certificate()));
  EXPECT_EQ(entry0.intermediates_size(), entry1.intermediates_size());
  for (int i = 0; i < entry0.intermediates_size(); ++i)
    EXPECT_EQ(H(entry0.intermediates(i)), H(entry1.intermediates(i)));
}

typedef testing::Types<FileDB, SQLiteDB> Databases;

TYPED_TEST_CASE(FrontendSignerTest, Databases);

TYPED_TEST(FrontendSignerTest, Log) {
  CertificateEntry entry0, entry1;
  this->test_signer_.CreateUnique(&entry0);
  this->test_signer_.CreateUnique(&entry1);

  // Log and expect success.
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry0, NULL));
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry1, NULL));

  // Look it up and expect to get the right thing back.
  LoggedCertificate logged_cert0, logged_cert1;
  string hash0 = Sha256Hasher::Sha256Digest(entry0.leaf_certificate());
  string hash1 = Sha256Hasher::Sha256Digest(entry1.leaf_certificate());

  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupCertificateByHash(hash0, &logged_cert0));
  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupCertificateByHash(hash1, &logged_cert1));

  CompareEntries(entry0, logged_cert0.sct().entry());
  CompareEntries(entry1, logged_cert1.sct().entry());
}

TYPED_TEST(FrontendSignerTest, Time) {
  CertificateEntry entry0, entry1;
  this->test_signer_.CreateUnique(&entry0);
  this->test_signer_.CreateUnique(&entry1);

  // Log and expect success.
  SignedCertificateTimestamp sct0, sct1;
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry0, &sct0));
  EXPECT_LE(sct0.timestamp(), util::TimeInMilliseconds());
  EXPECT_GT(sct0.timestamp(), 0U);

  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry1, &sct1));
  EXPECT_LE(sct0.timestamp(), sct1.timestamp());
  EXPECT_LE(sct1.timestamp(), util::TimeInMilliseconds());
}

TYPED_TEST(FrontendSignerTest, LogDuplicates) {
  CertificateEntry entry;
  this->test_signer_.CreateUnique(&entry);

  SignedCertificateTimestamp sct0, sct1;
  // Log and expect success.
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry, &sct0));
  // Wait for time to change.
  usleep(2000);
  // Try to log again.
  EXPECT_EQ(FrontendSigner::DUPLICATE,
            this->frontend_->QueueEntry(entry, &sct1));

  // Expect to get the original timestamp.
  EXPECT_EQ(sct0.timestamp(), sct1.timestamp());
}

TYPED_TEST(FrontendSignerTest, LogDuplicatesDifferentChain) {
  CertificateEntry entry0, entry1;
  this->test_signer_.CreateUnique(&entry0);
  entry1.CopyFrom(entry0);
  entry1.add_intermediates(this->test_signer_.UniqueFakeCertBytestring());

  SignedCertificateTimestamp sct0, sct1;
  // Log and expect success.
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry0, &sct0));
  // Wait for time to change.
  usleep(2000);
  // Try to log again.
  EXPECT_EQ(FrontendSigner::DUPLICATE,
            this->frontend_->QueueEntry(entry1, &sct1));

  // Expect to get the original timestamp.
  EXPECT_EQ(sct0.timestamp(), sct1.timestamp());
}

TYPED_TEST(FrontendSignerTest, Verify) {
  CertificateEntry entry0, entry1;
  this->test_signer_.CreateUnique(&entry0);
  this->test_signer_.CreateUnique(&entry1);

  // Log and expect success.
  SignedCertificateTimestamp sct0, sct1;
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry0, &sct0));
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry1, &sct1));

  // Verify results.
  // Copy the submitted entry to the SCT.
  sct0.mutable_entry()->CopyFrom(entry0);
  sct1.mutable_entry()->CopyFrom(entry1);

  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(sct0),
            LogVerifier::VERIFY_OK);
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(sct1),
            LogVerifier::VERIFY_OK);

  // Swap the data and expect failure.
  SignedCertificateTimestamp wrong_sct(sct0);
  wrong_sct.mutable_entry()->CopyFrom(entry1);
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(wrong_sct),
            LogVerifier::INVALID_SIGNATURE);
}

TYPED_TEST(FrontendSignerTest, TimedVerify) {
  CertificateEntry entry0, entry1;
  this->test_signer_.CreateUnique(&entry0);
  this->test_signer_.CreateUnique(&entry1);

  uint64_t past_time = util::TimeInMilliseconds();
  usleep(2000);

  // Log and expect success.
  SignedCertificateTimestamp sct0, sct1;
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry0, &sct0));
  // Make sure we get different timestamps.
  usleep(2000);
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry1, &sct1));

  EXPECT_GT(sct1.timestamp(), sct0.timestamp());

  // Verify.
  // Copy the submitted entry to the SCT.
  sct0.mutable_entry()->CopyFrom(entry0);
  sct1.mutable_entry()->CopyFrom(entry1);
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(sct0),
            LogVerifier::VERIFY_OK);
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(sct1),
            LogVerifier::VERIFY_OK);

  // Go back to the past and expect verification to fail (since the sct is
  // from the future).
  EXPECT_EQ(this->verifier_->
            VerifySignedCertificateTimestamp(sct0, 0, past_time),
            LogVerifier::INVALID_TIMESTAMP);

  // Swap timestamps and expect failure.
  SignedCertificateTimestamp wrong_sct(sct0);
  wrong_sct.set_timestamp(sct1.timestamp());
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(wrong_sct),
            LogVerifier::INVALID_SIGNATURE);
}

}  // namespace

int main(int argc, char**argv) {
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
