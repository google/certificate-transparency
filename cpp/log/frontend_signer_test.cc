/* -*- indent-tabs-mode: nil -*- */
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <string>

#include "log/file_db.h"
#include "log/fake_consistent_store.h"
#include "log/frontend_signer.h"
#include "log/log_verifier.h"
#include "log/logged_certificate.h"
#include "log/sqlite_db.h"
#include "log/test_db.h"
#include "log/test_signer.h"
#include "merkletree/merkle_verifier.h"
#include "merkletree/serial_hasher.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"
#include "util/testing.h"
#include "util/status.h"
#include "util/util.h"

namespace {

using cert_trans::ConsistentStore;
using cert_trans::EntryHandle;
using cert_trans::FakeConsistentStore;
using cert_trans::LoggedCertificate;
using ct::LogEntry;
using ct::SignedCertificateTimestamp;
using std::string;
using std::vector;

typedef Database<LoggedCertificate> DB;
typedef FrontendSigner FS;

template <class T>
class FrontendSignerTest : public ::testing::Test {
 protected:
  FrontendSignerTest()
      : test_db_(),
        test_signer_(),
        verifier_(TestSigner::DefaultLogSigVerifier(),
                  new MerkleVerifier(new Sha256Hasher())),
        store_("id"),
        frontend_(db(), &store_, TestSigner::DefaultLogSigner()) {
  }

  T* db() const {
    return test_db_.db();
  }

  TestDB<T> test_db_;
  TestSigner test_signer_;
  LogVerifier verifier_;
  FakeConsistentStore<LoggedCertificate> store_;
  FS frontend_;
};

typedef testing::Types<FileDB<LoggedCertificate>, SQLiteDB<LoggedCertificate>>
    Databases;

TYPED_TEST_CASE(FrontendSignerTest, Databases);

TYPED_TEST(FrontendSignerTest, LogKatTest) {
  LogEntry default_entry;
  this->test_signer_.SetDefaults(&default_entry);

  // Log and expect success.
  EXPECT_EQ(FS::NEW, this->frontend_.QueueEntry(default_entry, NULL));

  // Look it up and expect to get the right thing back.
  string hash =
      Sha256Hasher::Sha256Digest(Serializer::LeafCertificate(default_entry));
  EntryHandle<LoggedCertificate> entry_handle;
  EXPECT_TRUE(this->store_.GetPendingEntryForHash(hash, &entry_handle).ok());
  const LoggedCertificate& logged_cert(entry_handle.Entry());

  TestSigner::TestEqualEntries(default_entry, logged_cert.entry());
}

TYPED_TEST(FrontendSignerTest, Log) {
  LogEntry entry0, entry1;
  this->test_signer_.CreateUnique(&entry0);
  this->test_signer_.CreateUnique(&entry1);

  // Log and expect success.
  EXPECT_EQ(FS::NEW, this->frontend_.QueueEntry(entry0, NULL));
  EXPECT_EQ(FS::NEW, this->frontend_.QueueEntry(entry1, NULL));

  // Look it up and expect to get the right thing back.
  string hash0 =
      Sha256Hasher::Sha256Digest(Serializer::LeafCertificate(entry0));
  string hash1 =
      Sha256Hasher::Sha256Digest(Serializer::LeafCertificate(entry1));

  EntryHandle<LoggedCertificate> entry_handle0;
  EntryHandle<LoggedCertificate> entry_handle1;
  EXPECT_TRUE(this->store_.GetPendingEntryForHash(hash0, &entry_handle0).ok());
  EXPECT_TRUE(this->store_.GetPendingEntryForHash(hash1, &entry_handle1).ok());
  const LoggedCertificate& logged_cert0(entry_handle0.Entry());
  const LoggedCertificate& logged_cert1(entry_handle1.Entry());

  TestSigner::TestEqualEntries(entry0, logged_cert0.entry());
  TestSigner::TestEqualEntries(entry1, logged_cert1.entry());
}

TYPED_TEST(FrontendSignerTest, Time) {
  LogEntry entry0, entry1;
  this->test_signer_.CreateUnique(&entry0);
  this->test_signer_.CreateUnique(&entry1);

  // Log and expect success.
  SignedCertificateTimestamp sct0, sct1;
  EXPECT_EQ(FS::NEW, this->frontend_.QueueEntry(entry0, &sct0));
  EXPECT_LE(sct0.timestamp(), util::TimeInMilliseconds());
  EXPECT_GT(sct0.timestamp(), 0U);

  EXPECT_EQ(FS::NEW, this->frontend_.QueueEntry(entry1, &sct1));
  EXPECT_LE(sct0.timestamp(), sct1.timestamp());
  EXPECT_LE(sct1.timestamp(), util::TimeInMilliseconds());
}

TYPED_TEST(FrontendSignerTest, LogDuplicates) {
  LogEntry entry;
  this->test_signer_.CreateUnique(&entry);

  SignedCertificateTimestamp sct0, sct1;
  // Log and expect success.
  EXPECT_EQ(FS::NEW, this->frontend_.QueueEntry(entry, &sct0));
  // Wait for time to change.
  usleep(2000);
  // Try to log again.
  EXPECT_EQ(FS::DUPLICATE, this->frontend_.QueueEntry(entry, &sct1));

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
  EXPECT_EQ(FS::NEW, this->frontend_.QueueEntry(entry0, &sct0));
  // Wait for time to change.
  usleep(2000);
  // Try to log again.
  EXPECT_EQ(FS::DUPLICATE, this->frontend_.QueueEntry(entry1, &sct1));

  // Expect to get the original timestamp.
  EXPECT_EQ(sct0.timestamp(), sct1.timestamp());
}

TYPED_TEST(FrontendSignerTest, Verify) {
  LogEntry entry0, entry1;
  this->test_signer_.CreateUnique(&entry0);
  this->test_signer_.CreateUnique(&entry1);

  // Log and expect success.
  SignedCertificateTimestamp sct0, sct1;
  EXPECT_EQ(FS::NEW, this->frontend_.QueueEntry(entry0, &sct0));
  EXPECT_EQ(FS::NEW, this->frontend_.QueueEntry(entry1, &sct1));

  // Verify results.

  EXPECT_EQ(this->verifier_.VerifySignedCertificateTimestamp(entry0, sct0),
            LogVerifier::VERIFY_OK);
  EXPECT_EQ(this->verifier_.VerifySignedCertificateTimestamp(entry1, sct1),
            LogVerifier::VERIFY_OK);

  // Swap the data and expect failure.
  EXPECT_EQ(this->verifier_.VerifySignedCertificateTimestamp(entry0, sct1),
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
  EXPECT_EQ(FS::NEW, this->frontend_.QueueEntry(entry0, &sct0));
  // Make sure we get different timestamps.
  usleep(2000);
  EXPECT_EQ(FS::NEW, this->frontend_.QueueEntry(entry1, &sct1));

  EXPECT_GT(sct1.timestamp(), sct0.timestamp());

  // Verify.
  EXPECT_EQ(this->verifier_.VerifySignedCertificateTimestamp(entry0, sct0),
            LogVerifier::VERIFY_OK);
  EXPECT_EQ(this->verifier_.VerifySignedCertificateTimestamp(entry1, sct1),
            LogVerifier::VERIFY_OK);

  // Go back to the past and expect verification to fail (since the sct is
  // from the future).
  EXPECT_EQ(this->verifier_.VerifySignedCertificateTimestamp(entry0, sct0, 0,
                                                             past_time),
            LogVerifier::INVALID_TIMESTAMP);

  // Swap timestamps and expect failure.
  SignedCertificateTimestamp wrong_sct(sct0);
  wrong_sct.set_timestamp(sct1.timestamp());
  EXPECT_EQ(this->verifier_.VerifySignedCertificateTimestamp(entry0,
                                                             wrong_sct),
            LogVerifier::INVALID_SIGNATURE);
}

}  // namespace

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
