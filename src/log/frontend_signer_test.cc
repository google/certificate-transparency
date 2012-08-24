#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stddef.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "ct.pb.h"
#include "frontend_signer.h"
#include "log_db.h"
#include "log_signer.h"
#include "log_verifier.h"
#include "merkle_verifier.h"
#include "test_db.h"
#include "types.h"
#include "util.h"

namespace {

const char *ecp256_private_key = {
  "-----BEGIN EC PRIVATE KEY-----\n"
  "MHcCAQEEIG8QAquNnarN6Ik2cMIZtPBugh9wNRe0e309MCmDfBGuoAoGCCqGSM49\n"
  "AwEHoUQDQgAES0AfBkjr7b8b19p5Gk8plSAN16wWXZyhYsH6FMCEUK60t7pem/ck\n"
  "oPX8hupuaiJzJS0ZQ0SEoJGlFxkUFwft5g==\n"
  "-----END EC PRIVATE KEY-----\n"
};

const char *ecp256_public_key = {
  "-----BEGIN PUBLIC KEY-----\n"
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES0AfBkjr7b8b19p5Gk8plSAN16wW\n"
  "XZyhYsH6FMCEUK60t7pem/ckoPX8hupuaiJzJS0ZQ0SEoJGlFxkUFwft5g==\n"
  "-----END PUBLIC KEY-----\n"
};

EVP_PKEY* PrivateKeyFromPem(const std::string &pemkey) {
  BIO *bio = BIO_new_mem_buf(const_cast<char*>(pemkey.data()), pemkey.size());
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  assert(pkey != NULL);
  BIO_free(bio);
  return pkey;
}

EVP_PKEY* PublicKeyFromPem(const std::string &pemkey) {
  BIO *bio = BIO_new_mem_buf(const_cast<char*>(pemkey.data()), pemkey.size());
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  assert(pkey != NULL);
  BIO_free(bio);
  return pkey;
}

template <class T>
class FrontendSignerTest : public ::testing::Test {
 protected:
  FrontendSignerTest()
      : verifier_(NULL),
        frontend_(NULL) {}

  void SetUp() {
    EVP_PKEY *pkey = PrivateKeyFromPem(ecp256_private_key);
    EVP_PKEY *pubkey = PublicKeyFromPem(ecp256_public_key);
    verifier_ = new LogVerifier(new LogSigVerifier(pubkey),
                                new MerkleVerifier(new Sha256Hasher()));
    LogDB *db = t_.GetDB();
    ASSERT_TRUE(db != NULL);
    frontend_ = new FrontendSigner(db, new LogSigner(pkey));
    ASSERT_TRUE(verifier_ != NULL);
    ASSERT_TRUE(frontend_ != NULL);
  }

  ~FrontendSignerTest() {
    delete verifier_;
    delete frontend_;
  }

  LogVerifier *verifier_;
  FrontendSigner *frontend_;
  T t_;
};

typedef ::testing::Types<TestMemoryDB, TestFileDB> LogDBImplementations;

TYPED_TEST_CASE(FrontendSignerTest, LogDBImplementations);

const byte unicorn[] = "Unicorn";
const byte alice[] = "Alice";

TYPED_TEST(FrontendSignerTest, Log) {
  const bstring kUnicorn(unicorn, 7);
  const bstring kAlice(alice, 5);

  // Log and expect success.
  SignedCertificateHash sch0, sch1;
  EXPECT_EQ(this->frontend_->QueueEntry(kUnicorn, &sch0), LogDB::NEW);
  EXPECT_EQ(sch0.entry().type(), CertificateEntry::X509_ENTRY);
  EXPECT_EQ(sch0.entry().leaf_certificate(), kUnicorn);

  EXPECT_EQ(this->frontend_->QueueEntry(kAlice, &sch1), LogDB::NEW);
  EXPECT_EQ(sch1.entry().type(), CertificateEntry::X509_ENTRY);
  EXPECT_EQ(sch1.entry().leaf_certificate(), kAlice);
}

TYPED_TEST(FrontendSignerTest, Time) {
  const bstring kUnicorn(unicorn, 7);
  const bstring kAlice(alice, 5);

  // Log and expect success.
  SignedCertificateHash sch0, sch1;
  EXPECT_EQ(this->frontend_->QueueEntry(kUnicorn, &sch0), LogDB::NEW);
  EXPECT_LE(sch0.timestamp(), util::TimeInMilliseconds());
  EXPECT_GT(sch0.timestamp(), 0U);

  EXPECT_EQ(this->frontend_->QueueEntry(kAlice, &sch1), LogDB::NEW);
  EXPECT_LE(sch0.timestamp(), sch1.timestamp());
  EXPECT_LE(sch1.timestamp(), util::TimeInMilliseconds());
}

TYPED_TEST(FrontendSignerTest, LogDuplicates) {
  const bstring kUnicorn(unicorn, 7);

  SignedCertificateHash sch0, sch1;
  // Log and expect success.
  EXPECT_EQ(this->frontend_->QueueEntry(kUnicorn, &sch0), LogDB::NEW);
  // Wait for time to change.
  usleep(2000);
  // Try to log again.
  EXPECT_EQ(this->frontend_->QueueEntry(kUnicorn, &sch1),
            LogDB::PENDING);

  EXPECT_EQ(sch0.entry().type(), sch1.entry().type());
  EXPECT_EQ(sch0.entry().leaf_certificate(), sch1.entry().leaf_certificate());
  // Expect to get the original timestamp.
  EXPECT_EQ(sch0.timestamp(), sch1.timestamp());
}

// TODO: KATs.
TYPED_TEST(FrontendSignerTest, Verify) {
  const bstring kUnicorn(unicorn, 7);
  const bstring kAlice(alice, 5);

  // Log and expect success.
  SignedCertificateHash sch, sch2;
  EXPECT_EQ(this->frontend_->QueueEntry(kUnicorn, &sch), LogDB::NEW);
  EXPECT_EQ(this->frontend_->QueueEntry(CertificateEntry::PRECERT_ENTRY,
                                        kAlice, &sch2), LogDB::NEW);

  // Verify results.
  EXPECT_EQ(this->verifier_->VerifySignedCertificateHash(sch),
            LogVerifier::VERIFY_OK);
  EXPECT_EQ(this->verifier_->VerifySignedCertificateHash(sch2),
            LogVerifier::VERIFY_OK);

  // Swap the data and expect failure.
  SignedCertificateHash wrong_sch(sch);
  wrong_sch.mutable_entry()->CopyFrom(sch2.entry());
  EXPECT_EQ(this->verifier_->VerifySignedCertificateHash(wrong_sch),
            LogVerifier::INVALID_SIGNATURE);
}

TYPED_TEST(FrontendSignerTest, TimedVerify) {
  const bstring kUnicorn(unicorn, 7);
  const bstring kAlice(alice, 5);

  uint64_t past_time = util::TimeInMilliseconds();
  usleep(2000);

  // Log and expect success.
  SignedCertificateHash sch, sch2;
  EXPECT_EQ(this->frontend_->QueueEntry(kUnicorn, &sch), LogDB::NEW);
  // Make sure we get different timestamps.
  usleep(2000);
  EXPECT_EQ(this->frontend_->QueueEntry(CertificateEntry::PRECERT_ENTRY,
                                        kAlice, &sch2), LogDB::NEW);

  EXPECT_GT(sch2.timestamp(), sch.timestamp());

  // Verify.
  EXPECT_EQ(this->verifier_->VerifySignedCertificateHash(sch),
            LogVerifier::VERIFY_OK);
  EXPECT_EQ(this->verifier_->VerifySignedCertificateHash(sch2),
            LogVerifier::VERIFY_OK);

  // Go back to the past and expect verification to fail (since the sch is
  // from the future).
  EXPECT_EQ(this->verifier_->VerifySignedCertificateHash(sch, 0, past_time),
            LogVerifier::INVALID_TIMESTAMP);

  // Swap timestamps and expect failure.
  SignedCertificateHash wrong_sch(sch);
  wrong_sch.set_timestamp(sch2.timestamp());
  EXPECT_EQ(this->verifier_->VerifySignedCertificateHash(wrong_sch),
            LogVerifier::INVALID_SIGNATURE);
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
