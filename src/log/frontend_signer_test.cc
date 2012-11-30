/* -*- indent-tabs-mode: nil -*- */
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <string>

#include "log/file_db.h"
#include "log/frontend_signer.h"
#include "log_verifier.h"
#include "log/sqlite_db.h"
#include "log/test_db.h"
#include "log/test_signer.h"
#include "merkletree/merkle_verifier.h"
#include "merkletree/serial_hasher.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"
#include "util/testing.h"
#include "util/util.h"

namespace {

using ct::LogEntry;
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

typedef testing::Types<FileDB, SQLiteDB> Databases;

TYPED_TEST_CASE(FrontendSignerTest, Databases);

TYPED_TEST(FrontendSignerTest, LogKatTest) {
  LogEntry default_entry;
  this->test_signer_.SetDefaults(&default_entry);

  // Log and expect success.
  EXPECT_EQ(FrontendSigner::NEW,
            this->frontend_->QueueEntry(default_entry, NULL));

  // Look it up and expect to get the right thing back.
  LoggedCertificate logged_cert;
  string hash =
      Sha256Hasher::Sha256Digest(Serializer::LeafCertificate(default_entry));

  EXPECT_EQ(Database::LOOKUP_OK, this->db()->LookupByHash(hash, &logged_cert));

  TestSigner::TestEqualEntries(default_entry, logged_cert.entry());
}

TYPED_TEST(FrontendSignerTest, Log) {
  LogEntry entry0, entry1;
  this->test_signer_.CreateUnique(&entry0);
  this->test_signer_.CreateUnique(&entry1);

  // Log and expect success.
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry0, NULL));
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry1, NULL));

  // Look it up and expect to get the right thing back.
  LoggedCertificate logged_cert0, logged_cert1;
  string hash0 =
      Sha256Hasher::Sha256Digest(Serializer::LeafCertificate(entry0));
  string hash1 =
      Sha256Hasher::Sha256Digest(Serializer::LeafCertificate(entry1));

  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupByHash(hash0, &logged_cert0));
  EXPECT_EQ(Database::LOOKUP_OK,
            this->db()->LookupByHash(hash1, &logged_cert1));

  TestSigner::TestEqualEntries(entry0, logged_cert0.entry());
  TestSigner::TestEqualEntries(entry1, logged_cert1.entry());
}

TYPED_TEST(FrontendSignerTest, Time) {
  LogEntry entry0, entry1;
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
  LogEntry entry;
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
  LogEntry entry0, entry1;
  this->test_signer_.CreateUnique(&entry0);
  entry1.CopyFrom(entry0);
  if (entry1.type() == ct::X509_ENTRY) {
    entry1.mutable_x509_entry()->add_certificate_chain(
        this->test_signer_.UniqueFakeCertBytestring());
  } else {
    CHECK_EQ(ct::PRECERT_ENTRY, entry1.type());
    entry1.mutable_precert_entry()->add_precertificate_chain(
        this->test_signer_.UniqueFakeCertBytestring());
  }

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
  LogEntry entry0, entry1;
  this->test_signer_.CreateUnique(&entry0);
  this->test_signer_.CreateUnique(&entry1);

  // Log and expect success.
  SignedCertificateTimestamp sct0, sct1;
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry0, &sct0));
  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(entry1, &sct1));

  // Verify results.

  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(entry0, sct0),
            LogVerifier::VERIFY_OK);
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(entry1, sct1),
            LogVerifier::VERIFY_OK);

  // Swap the data and expect failure.
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(entry0, sct1),
            LogVerifier::INVALID_SIGNATURE);
}

TYPED_TEST(FrontendSignerTest, TimedVerify) {
  LogEntry entry0, entry1;
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
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(entry0, sct0),
            LogVerifier::VERIFY_OK);
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(entry1, sct1),
            LogVerifier::VERIFY_OK);

  // Go back to the past and expect verification to fail (since the sct is
  // from the future).
  EXPECT_EQ(this->verifier_->
            VerifySignedCertificateTimestamp(entry0, sct0, 0, past_time),
            LogVerifier::INVALID_TIMESTAMP);

  // Swap timestamps and expect failure.
  SignedCertificateTimestamp wrong_sct(sct0);
  wrong_sct.set_timestamp(sct1.timestamp());
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(entry0,
                                                              wrong_sct),
            LogVerifier::INVALID_SIGNATURE);
}

}  // namespace

int main(int argc, char**argv) {
  ct::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
