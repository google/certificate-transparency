#include <glog/logging.h>
#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stddef.h>
#include <string>

#include "file_db.h"
#include "file_storage.h"
#include "log_lookup.h"
#include "log_signer.h"
#include "log_verifier.h"
#include "merkle_verifier.h"
#include "serial_hasher.h"
#include "sqlite_db.h"
#include "tree_signer.h"
#include "util.h"

namespace {

using ct::CertificateEntry;
using ct::LoggedCertificate;
using ct::MerkleAuditProof;
using std::string;

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

EVP_PKEY* PrivateKeyFromPem(const string &pemkey) {
  BIO *bio = BIO_new_mem_buf(const_cast<char*>(pemkey.data()), pemkey.size());
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  assert(pkey != NULL);
  BIO_free(bio);
  return pkey;
}

EVP_PKEY* PublicKeyFromPem(const string &pemkey) {
  BIO *bio = BIO_new_mem_buf(const_cast<char*>(pemkey.data()), pemkey.size());
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  assert(pkey != NULL);
  BIO_free(bio);
  return pkey;
}

const unsigned kCertStorageDepth = 3;
const unsigned kTreeStorageDepth = 8;

template <class T> class LogLookupTest : public ::testing::Test {
 protected:
  LogLookupTest()
      : db_(NULL),
        tree_signer_(NULL),
        verifier_(NULL) {}

  void SetUp() {
    EVP_PKEY *pkey = PrivateKeyFromPem(ecp256_private_key);
    EVP_PKEY *pubkey = PublicKeyFromPem(ecp256_public_key);
    verifier_ = new LogVerifier(new LogSigVerifier(pubkey),
                                new MerkleVerifier(new Sha256Hasher()));
    file_base_ = util::CreateTemporaryDirectory("/tmp/ctlogXXXXXX");
    ASSERT_EQ("/tmp/ctlog", file_base_.substr(0, 10));
    ASSERT_EQ(16U, file_base_.length());

    NewDB();

    tree_signer_ = new TreeSigner(db_, new LogSigner(pkey));
    ASSERT_TRUE(verifier_ != NULL);
    ASSERT_TRUE(tree_signer_ != NULL);
  }

  void NewDB();

  void TearDown() {
    // Check again that it is safe to empty file_base_.
    ASSERT_EQ("/tmp/ctlog", file_base_.substr(0, 10));
    ASSERT_EQ(16U, file_base_.length());
    string command = "rm -r " + file_base_;
    int ret = system(command.c_str());
    if (ret != 0)
      std::cout << "Failed to delete temporary directory in "
                << file_base_ << std::endl;
  }

  ~LogLookupTest() {
    delete tree_signer_;
    delete verifier_;
    delete db_;
  }

  Database *db_;
  TreeSigner *tree_signer_;
  LogVerifier *verifier_;
  string file_base_;
};

template <> void LogLookupTest<FileDB>::NewDB() {
  string certs_dir = file_base_ + "/certs";
  string tree_dir = file_base_ + "/tree";
  int ret = mkdir(certs_dir.c_str(), 0700);
  ASSERT_EQ(ret, 0);
  ret = mkdir(tree_dir.c_str(), 0700);
  ASSERT_EQ(ret, 0);

  db_ = new FileDB(new FileStorage(certs_dir, kCertStorageDepth),
                   new FileStorage(tree_dir, kTreeStorageDepth));
}

template <> void LogLookupTest<SQLiteDB>::NewDB() {
  db_ = new SQLiteDB(file_base_ + "/ct");
}

typedef testing::Types<FileDB, SQLiteDB> Databases;

TYPED_TEST_CASE(LogLookupTest, Databases);

// TODO(ekasper): use real data.
TYPED_TEST(LogLookupTest, Lookup) {
  string hash("1234xyzw", 8);
  string wrong_hash("1234xyzq", 8);

  LoggedCertificate logged_cert;
  logged_cert.set_certificate_sha256_hash(hash);
  logged_cert.mutable_sct()->set_timestamp(1234);
  logged_cert.mutable_sct()->mutable_entry()->set_type(
      CertificateEntry::X509_ENTRY);
  logged_cert.mutable_sct()->mutable_entry()->set_leaf_certificate("cert");

  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(logged_cert));

  MerkleAuditProof proof;
  EXPECT_EQ(TreeSigner::OK, this->tree_signer_->UpdateTree());

  LogLookup lookup(this->db_);
  // Look the new entry up.
  EXPECT_EQ(LogLookup::OK, lookup.CertificateAuditProof(1234, hash, &proof));
}

TYPED_TEST(LogLookupTest, NotFound) {
  string hash("1234xyzw", 8);
  string wrong_hash("1234xyzq", 8);

  LoggedCertificate logged_cert;
  logged_cert.set_certificate_sha256_hash(hash);
  logged_cert.mutable_sct()->set_timestamp(1234);
  logged_cert.mutable_sct()->mutable_entry()->set_type(
      CertificateEntry::X509_ENTRY);
  logged_cert.mutable_sct()->mutable_entry()->set_leaf_certificate("cert");

  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(logged_cert));

  MerkleAuditProof proof;
  EXPECT_EQ(TreeSigner::OK, this->tree_signer_->UpdateTree());

  LogLookup lookup(this->db_);

  // Look up stuff that's not in the DB.
  EXPECT_EQ(LogLookup::NOT_FOUND,
            lookup.CertificateAuditProof(1234, wrong_hash, &proof));
  EXPECT_EQ(LogLookup::NOT_FOUND,
            lookup.CertificateAuditProof(1235, hash, &proof));
}

TYPED_TEST(LogLookupTest, Update) {
  string hash("1234xyzw", 8);

  LogLookup lookup(this->db_);

  LoggedCertificate logged_cert;
  logged_cert.set_certificate_sha256_hash(hash);
  logged_cert.mutable_sct()->set_timestamp(1234);
  logged_cert.mutable_sct()->mutable_entry()->set_type(
      CertificateEntry::X509_ENTRY);
  logged_cert.mutable_sct()->mutable_entry()->set_leaf_certificate("cert");

  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(logged_cert));

  MerkleAuditProof proof;
  EXPECT_EQ(TreeSigner::OK, this->tree_signer_->UpdateTree());

  // There is an entry but we don't know about it yet.
  EXPECT_EQ(LogLookup::NOT_FOUND,
            lookup.CertificateAuditProof(1234, hash, &proof));
  // Update
  EXPECT_EQ(LogLookup::UPDATE_OK, lookup.Update());
  // Look the new entry up.
  EXPECT_EQ(LogLookup::OK, lookup.CertificateAuditProof(1234, hash, &proof));
}

// Verify that the audit proof constructed is correct (assuming the signer
// operates correctly). TODO(ekasper): KAT tests.
TYPED_TEST(LogLookupTest, Verify) {
  string hash("1234xyzw", 8);
  string wrong_hash("1234xyzq", 8);

  LoggedCertificate logged_cert;
  logged_cert.set_certificate_sha256_hash(hash);
  logged_cert.mutable_sct()->set_timestamp(1234);
  logged_cert.mutable_sct()->mutable_entry()->set_type(
      CertificateEntry::X509_ENTRY);
  logged_cert.mutable_sct()->mutable_entry()->set_leaf_certificate("cert");

  EXPECT_EQ(Database::OK,
            this->db_->CreatePendingCertificateEntry(logged_cert));

  EXPECT_EQ(TreeSigner::OK, this->tree_signer_->UpdateTree());

  LogLookup lookup(this->db_);
  MerkleAuditProof proof;
  // Look the new entry up.
  EXPECT_EQ(LogLookup::OK, lookup.CertificateAuditProof(1234, hash, &proof));
  EXPECT_EQ(LogVerifier::VERIFY_OK,
            this->verifier_->VerifyMerkleAuditProof(logged_cert.sct(), proof));
}

// Build a bigger tree so that we actually verify a non-empty path.
TYPED_TEST(LogLookupTest, VerifyWithPath) {
  string hash("1234xyzw", 8);
  string cert("certificate", 11);

  LoggedCertificate logged_certs[13];

  // Make the tree not balanced for extra fun.
  for (int i = 0; i < 13; ++i) {
    logged_certs[i].set_certificate_sha256_hash(hash + static_cast<char>(i));
    logged_certs[i].mutable_sct()->set_timestamp(1234 + i);
    logged_certs[i].mutable_sct()->mutable_entry()->set_type(
        CertificateEntry::X509_ENTRY);
    logged_certs[i].mutable_sct()->mutable_entry()->
        set_leaf_certificate(cert + static_cast<char>(i));

    EXPECT_EQ(Database::OK,
              this->db_->CreatePendingCertificateEntry(logged_certs[i]));
  }

  EXPECT_EQ(TreeSigner::OK, this->tree_signer_->UpdateTree());

  LogLookup lookup(this->db_);
  MerkleAuditProof proof;

  for (int i = 0; i < 2; ++i) {
    EXPECT_EQ(LogLookup::OK,
              lookup.CertificateAuditProof(1234 + i,
                                           hash + static_cast<char>(i),
                                           &proof));
    EXPECT_EQ(LogVerifier::VERIFY_OK,
              this->verifier_->VerifyMerkleAuditProof(logged_certs[i].sct(),
                                                      proof));
  }
}

}  // namespace
int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
