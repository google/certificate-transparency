#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <string>

#include "ct.pb.h"
#include "file_db.h"
#include "file_storage.h"
#include "log_signer.h"
#include "log_verifier.h"
#include "merkle_verifier.h"
#include "tree_signer.h"
#include "types.h"
#include "util.h"

namespace {

using ct::CertificateEntry;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;

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

const unsigned kCertStorageDepth = 3;
const unsigned kTreeStorageDepth = 8;

class TreeSignerTest : public ::testing::Test {
 protected:
  TreeSignerTest()
      : file_db_(NULL),
        verifier_(NULL),
        tree_signer_(NULL) {}

  void SetUp() {
    EVP_PKEY *pkey = PrivateKeyFromPem(ecp256_private_key);
    EVP_PKEY *pubkey = PublicKeyFromPem(ecp256_public_key);
    verifier_ = new LogVerifier(new LogSigVerifier(pubkey),
                                new MerkleVerifier(new Sha256Hasher()));
    file_base_ = util::CreateTemporaryDirectory("/tmp/ctlogXXXXXX");
    ASSERT_EQ("/tmp/ctlog", file_base_.substr(0, 10));
    ASSERT_EQ(16U, file_base_.length());

    std::string certs_dir = file_base_ + "/certs";
    std::string tree_dir = file_base_ + "/tree";
    int ret = mkdir(certs_dir.c_str(), 0700);
    ASSERT_EQ(ret, 0);
    ret = mkdir(tree_dir.c_str(), 0700);
    ASSERT_EQ(ret, 0);

    file_db_ = new FileDB(new FileStorage(certs_dir, kCertStorageDepth),
                          new FileStorage(tree_dir, kTreeStorageDepth));

    tree_signer_ = new TreeSigner(file_db_, new LogSigner(pkey));
    ASSERT_TRUE(verifier_ != NULL);
    ASSERT_TRUE(tree_signer_ != NULL);
  }

  TreeSigner *GetSimilar() const {
    EVP_PKEY *pkey = PrivateKeyFromPem(ecp256_private_key);
    return new TreeSigner(file_db_, new LogSigner(pkey));
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

  ~TreeSignerTest() {
    delete verifier_;
    delete tree_signer_;
    delete file_db_;
  }

  FileDB *file_db_;
  LogVerifier *verifier_;
  TreeSigner *tree_signer_;
  std::string file_base_;
};

// TODO(ekasper): KAT tests.
TEST_F(TreeSignerTest, Sign) {
  bstring key("1234xyzw", 8);

  SignedCertificateTimestamp sct;
  sct.set_timestamp(1234);
  sct.mutable_entry()->set_type(CertificateEntry::X509_ENTRY);
  sct.mutable_entry()->set_leaf_certificate("certificate");

  EXPECT_EQ(Database::OK,
            file_db_->CreatePendingCertificateEntry(key, sct));

  EXPECT_EQ(TreeSigner::OK, tree_signer_->UpdateTree());

  SignedTreeHead sth;
  EXPECT_EQ(Database::LOGGED, file_db_->LatestTreeHead(&sth));
  EXPECT_EQ(1U, sth.tree_size());
  EXPECT_EQ(sth.timestamp(), tree_signer_->LastUpdateTime());
}

TEST_F(TreeSignerTest, Timestamp) {
  bstring key("1234xyzw", 8);

  SignedCertificateTimestamp sct;

  sct.set_timestamp(1234U);
  sct.mutable_entry()->set_type(CertificateEntry::X509_ENTRY);
  sct.mutable_entry()->set_leaf_certificate("certificate");

  EXPECT_EQ(Database::OK,
            file_db_->CreatePendingCertificateEntry(key, sct));

  EXPECT_EQ(TreeSigner::OK, tree_signer_->UpdateTree());
  uint64_t last_update = tree_signer_->LastUpdateTime();
  EXPECT_GE(last_update, 1234U);

  // Now create a second entry with a timestamp some time in the future
  // and verify that the signer's timestamp is greater than that.
  uint64_t future = last_update + 10000;
  sct.set_timestamp(future);
  bstring key2("1234abcd", 8);

  EXPECT_EQ(Database::OK,
            file_db_->CreatePendingCertificateEntry(key2, sct));
  EXPECT_EQ(TreeSigner::OK, tree_signer_->UpdateTree());
  EXPECT_GE(tree_signer_->LastUpdateTime(), future);
}

TEST_F(TreeSignerTest, Verify) {
  bstring key("1234xyzw", 8);

  SignedCertificateTimestamp sct;
  sct.set_timestamp(1234);
  sct.mutable_entry()->set_type(CertificateEntry::X509_ENTRY);
      sct.mutable_entry()->set_leaf_certificate("certificate");

  EXPECT_EQ(Database::OK,
            file_db_->CreatePendingCertificateEntry(key, sct));

  EXPECT_EQ(TreeSigner::OK, tree_signer_->UpdateTree());

  SignedTreeHead sth;
  EXPECT_EQ(Database::LOGGED, file_db_->LatestTreeHead(&sth));
  EXPECT_EQ(LogVerifier::VERIFY_OK, verifier_->VerifySignedTreeHead(sth));
}

TEST_F(TreeSignerTest, ResumeClean) {
  bstring key("1234xyzw", 8);

  SignedCertificateTimestamp sct;
  sct.set_timestamp(1234);
  sct.mutable_entry()->set_type(CertificateEntry::X509_ENTRY);
  sct.mutable_entry()->set_leaf_certificate("certificate");

  EXPECT_EQ(Database::OK,
            file_db_->CreatePendingCertificateEntry(key, sct));

  EXPECT_EQ(TreeSigner::OK, tree_signer_->UpdateTree());
  SignedTreeHead sth;

  EXPECT_EQ(Database::LOGGED, file_db_->LatestTreeHead(&sth));

  TreeSigner *signer2 = GetSimilar();
  EXPECT_EQ(signer2->LastUpdateTime(), sth.timestamp());

  // Update
  EXPECT_EQ(TreeSigner::OK, signer2->UpdateTree());
  SignedTreeHead sth2;

  EXPECT_EQ(Database::LOGGED, file_db_->LatestTreeHead(&sth2));
  EXPECT_LT(sth.timestamp(), sth2.timestamp());
  EXPECT_EQ(sth.root_hash(), sth2.root_hash());
  EXPECT_EQ(sth.tree_size(), sth2.tree_size());

  delete signer2;
}

// Test resuming when the tree head signature is lagging behind the
// sequence number commits.
TEST_F(TreeSignerTest, ResumePartialSign) {
  EXPECT_EQ(TreeSigner::OK, tree_signer_->UpdateTree());
  SignedTreeHead sth;
  EXPECT_EQ(Database::LOGGED, file_db_->LatestTreeHead(&sth));
  EXPECT_EQ(0U, sth.tree_size());

  // Log a pending entry.
  bstring key("1234xyzw", 8);
  SignedCertificateTimestamp sct;
  sct.set_timestamp(1234);
  sct.mutable_entry()->set_type(CertificateEntry::X509_ENTRY);
  sct.mutable_entry()->set_leaf_certificate("certificate");
  EXPECT_EQ(Database::OK,
            file_db_->CreatePendingCertificateEntry(key, sct));

  // Simulate the case where we assign a sequence number but fail
  // before signing.
  EXPECT_EQ(Database::OK,
            file_db_->AssignCertificateSequenceNumber(key, 0));

  TreeSigner *signer2 = GetSimilar();
  EXPECT_EQ(TreeSigner::OK, signer2->UpdateTree());
  SignedTreeHead sth2;
  EXPECT_EQ(Database::LOGGED, file_db_->LatestTreeHead(&sth2));
  // The signer should have picked up the sequence number commit.
  EXPECT_EQ(1U, sth2.tree_size());
  EXPECT_LT(sth.timestamp(), sth2.timestamp());
  EXPECT_NE(sth.root_hash(), sth2.root_hash());

  delete signer2;
}

TEST_F(TreeSignerTest, SignEmpty) {
  EXPECT_EQ(TreeSigner::OK, tree_signer_->UpdateTree());
  SignedTreeHead sth;

  EXPECT_EQ(Database::LOGGED, file_db_->LatestTreeHead(&sth));
  EXPECT_GT(sth.timestamp(), 0U);
  EXPECT_EQ(sth.tree_size(), 0U);
}

TEST_F(TreeSignerTest, FailInconsistentTreeHead) {
  EXPECT_EQ(TreeSigner::OK, tree_signer_->UpdateTree());
  // A second signer interferes.
  TreeSigner *signer2 = GetSimilar();
  EXPECT_EQ(TreeSigner::OK, signer2->UpdateTree());
  // The first signer should detect this and refuse to update.
  EXPECT_EQ(TreeSigner::DB_ERROR, tree_signer_->UpdateTree());

  delete signer2;
}

TEST_F(TreeSignerTest, FailInconsistentSequenceNumbers) {
  EXPECT_EQ(TreeSigner::OK, tree_signer_->UpdateTree());
  bstring key("1234xyzw", 8);

  SignedCertificateTimestamp sct;

  sct.set_timestamp(1234U);
  sct.mutable_entry()->set_type(CertificateEntry::X509_ENTRY);
  sct.mutable_entry()->set_leaf_certificate("certificate");

  EXPECT_EQ(Database::OK,
            file_db_->CreatePendingCertificateEntry(key, sct));
  // Assign a sequence number the signer does not know about.
  EXPECT_EQ(Database::OK,
            file_db_->AssignCertificateSequenceNumber(key, 0));

  // Create another pending entry.
  bstring key2("1234abcd", 8);
  EXPECT_EQ(Database::OK,
            file_db_->CreatePendingCertificateEntry(key2, sct));

  // Update should fail because we cannot commit a sequence number.
  EXPECT_EQ(TreeSigner::DB_ERROR, tree_signer_->UpdateTree());
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
