/* -*- indent-tabs-mode: nil -*- */

#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stddef.h>
#include <string>

#include "certificate_db.h"
#include "ct.pb.h"
#include "file_storage.h"
#include "frontend_signer.h"
#include "log_signer.h"
#include "log_verifier.h"
#include "merkle_verifier.h"
#include "types.h"
#include "util.h"

namespace {

using ct::CertificateEntry;
using ct::SignedCertificateTimestamp;

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

const unsigned kStorageDepth = 3;

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
    file_base_ = util::CreateTemporaryDirectory("/tmp/ctlogXXXXXX");
    ASSERT_EQ("/tmp/ctlog", file_base_.substr(0, 10));
    ASSERT_EQ(16U, file_base_.length());

    frontend_ = new FrontendSigner(new FileDB(new FileStorage(file_base_,
                                                              kStorageDepth)),
                                   new LogSigner(pkey));
    ASSERT_TRUE(verifier_ != NULL);
    ASSERT_TRUE(frontend_ != NULL);
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

  ~FrontendSignerTest() {
    delete verifier_;
    delete frontend_;
  }

  LogVerifier *verifier_;
  FrontendSigner *frontend_;
  std::string file_base_;
};

const byte unicorn[] = "Unicorn";
const byte alice[] = "Alice";

TEST_F(FrontendSignerTest, Log) {
  const bstring kUnicorn(unicorn, 7);
  const bstring kAlice(alice, 5);

  // Log and expect success.
  SignedCertificateTimestamp sct0, sct1;
  EXPECT_EQ(FrontendSigner::NEW,
            this->frontend_->QueueEntry(kUnicorn, &sct0));
  EXPECT_EQ(sct0.entry().type(), CertificateEntry::X509_ENTRY);
  EXPECT_EQ(sct0.entry().leaf_certificate(), kUnicorn);

  EXPECT_EQ(FrontendSigner::NEW,
            this->frontend_->QueueEntry(kAlice, &sct1));
  EXPECT_EQ(sct1.entry().type(), CertificateEntry::X509_ENTRY);
  EXPECT_EQ(sct1.entry().leaf_certificate(), kAlice);
}

TEST_F(FrontendSignerTest, Time) {
  const bstring kUnicorn(unicorn, 7);
  const bstring kAlice(alice, 5);

  // Log and expect success.
  SignedCertificateTimestamp sct0, sct1;
  EXPECT_EQ(FrontendSigner::NEW,
            this->frontend_->QueueEntry(kUnicorn, &sct0));
  EXPECT_LE(sct0.timestamp(), util::TimeInMilliseconds());
  EXPECT_GT(sct0.timestamp(), 0U);

  EXPECT_EQ(FrontendSigner::NEW, this->frontend_->QueueEntry(kAlice, &sct1));
  EXPECT_LE(sct0.timestamp(), sct1.timestamp());
  EXPECT_LE(sct1.timestamp(), util::TimeInMilliseconds());
}

TEST_F(FrontendSignerTest, LogDuplicates) {
  const bstring kUnicorn(unicorn, 7);

  SignedCertificateTimestamp sct0, sct1;
  // Log and expect success.
  EXPECT_EQ(FrontendSigner::NEW,
            this->frontend_->QueueEntry(kUnicorn, &sct0));
  // Wait for time to change.
  usleep(2000);
  // Try to log again.
  EXPECT_EQ(FrontendSigner::PENDING,
            this->frontend_->QueueEntry(kUnicorn, &sct1));

  EXPECT_EQ(sct0.entry().type(), sct1.entry().type());
  EXPECT_EQ(sct0.entry().leaf_certificate(), sct1.entry().leaf_certificate());
  // Expect to get the original timestamp.
  EXPECT_EQ(sct0.timestamp(), sct1.timestamp());
}

TEST_F(FrontendSignerTest, Verify) {
  const bstring kUnicorn(unicorn, 7);
  const bstring kAlice(alice, 5);

  // Log and expect success.
  SignedCertificateTimestamp sct, sct2;
  EXPECT_EQ(FrontendSigner::NEW,
            this->frontend_->QueueEntry(kUnicorn, &sct));
  EXPECT_EQ(FrontendSigner::NEW,
            this->frontend_->QueueEntry(CertificateEntry::PRECERT_ENTRY,
                                        kAlice, &sct2));

  // Verify results.
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(sct),
            LogVerifier::VERIFY_OK);
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(sct2),
            LogVerifier::VERIFY_OK);

  // Swap the data and expect failure.
  SignedCertificateTimestamp wrong_sct(sct);
  wrong_sct.mutable_entry()->CopyFrom(sct2.entry());
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(wrong_sct),
            LogVerifier::INVALID_SIGNATURE);
}

TEST_F(FrontendSignerTest, TimedVerify) {
  const bstring kUnicorn(unicorn, 7);
  const bstring kAlice(alice, 5);

  uint64_t past_time = util::TimeInMilliseconds();
  usleep(2000);

  // Log and expect success.
  SignedCertificateTimestamp sct, sct2;
  EXPECT_EQ(FrontendSigner::NEW,
            this->frontend_->QueueEntry(kUnicorn, &sct));
  // Make sure we get different timestamps.
  usleep(2000);
  EXPECT_EQ(FrontendSigner::NEW,
            this->frontend_->QueueEntry(CertificateEntry::PRECERT_ENTRY,
                                        kAlice, &sct2));

  EXPECT_GT(sct2.timestamp(), sct.timestamp());

  // Verify.
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(sct),
            LogVerifier::VERIFY_OK);
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(sct2),
            LogVerifier::VERIFY_OK);

  // Go back to the past and expect verification to fail (since the sct is
  // from the future).
  EXPECT_EQ(this->verifier_->
            VerifySignedCertificateTimestamp(sct, 0, past_time),
            LogVerifier::INVALID_TIMESTAMP);

  // Swap timestamps and expect failure.
  SignedCertificateTimestamp wrong_sct(sct);
  wrong_sct.set_timestamp(sct2.timestamp());
  EXPECT_EQ(this->verifier_->VerifySignedCertificateTimestamp(wrong_sct),
            LogVerifier::INVALID_SIGNATURE);
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
