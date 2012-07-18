#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stddef.h>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>

#include "../include/types.h"
#include "../log/log_signer.h"
#include "../util/util.h"
#include "LogDB.h"
#include "LogRecord.h"
#include "LogVerifier.h"
#include "MerkleTree.h"
#include "SerialHasher.h"
#include "TreeLogger.h"

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

// Set up files for the LogDB.
template <class T> void SetupDB() {}

template <class T> LogDB *CreateLogDB() {
  return new T();
}

// Clean up files written on disk.
// Does not delete the LogDB itself, since we pass its ownership to the logger.
template <class T> void DestroyDB() {}

template <> void SetupDB<FileDB>() {
  ASSERT_EQ(mkdir("/tmp/ct/b", 0777), 0);
}

template <> LogDB *CreateLogDB<FileDB>() {
  FileDB *file_db = new FileDB("/tmp/ct/b", 5);
  file_db->Init();
  return file_db;
}

template <> void DestroyDB<FileDB>() {
  ASSERT_EQ(system("rm -r /tmp/ct/b"), 0);
}

template <class T>
class TreeLoggerTest : public ::testing::Test {
 protected:
  TreeLoggerTest()
      : verifier_(NULL),
        tree_logger_(NULL) {}

  void SetUp() {
    EVP_PKEY *pkey = PrivateKeyFromPem(ecp256_private_key);
    EVP_PKEY *pubkey = PublicKeyFromPem(ecp256_public_key);
    SetupDB<T>();
    LogDB *db = CreateLogDB<T>();
    tree_logger_ = new TreeLogger(db, new LogSigner(pkey));
    verifier_ = new LogVerifier(new LogSigVerifier(pubkey));
    ASSERT_TRUE(tree_logger_ != NULL);
    ASSERT_TRUE(verifier_ != NULL);
  }

  void TearDown() {
    DestroyDB<T>();
  }

  ~TreeLoggerTest() {
    delete verifier_;
    delete tree_logger_;
  }

  LogVerifier *verifier_;
  TreeLogger *tree_logger_;
};

typedef ::testing::Types<MemoryDB, FileDB> LogDBImplementations;

TYPED_TEST_CASE(TreeLoggerTest, LogDBImplementations);

const unsigned char unicorn[] = "Unicorn";
const unsigned char alice[] = "Alice";

TYPED_TEST(TreeLoggerTest, LogAndVerifySegment) {
  const bstring kUnicorn(unicorn, 7);
  const bstring kAlice(alice, 5);

  bstring key0, key1;
  EXPECT_EQ(this->tree_logger_->QueueEntry(kUnicorn, &key0), LogDB::NEW);
  EXPECT_EQ(this->tree_logger_->QueueEntry(kAlice, &key1), LogDB::NEW);
  this->tree_logger_->LogSegment();
  bstring segment;
  EXPECT_EQ(this->tree_logger_->SegmentInfo(0, &segment), LogDB::LOGGED);
  EXPECT_FALSE(segment.empty());

  SegmentData data;
  EXPECT_TRUE(data.DeserializeSegmentInfo(segment));

  // Construct the trees.
  // (TODO: a monitor that can do this automatically.)
  MerkleTree log_segment_tree(new Sha256Hasher());
  bstring result0, result1;

  EXPECT_EQ(this->tree_logger_->EntryInfo(0, 0, &result0), LogDB::LOGGED);
  LogEntry *entry0 = LogEntry::Deserialize(result0);
  ASSERT_TRUE(entry0 != NULL);
  EXPECT_EQ(entry0->Type(), LogEntry::TEST_ENTRY);

  // Default submission handling signs the type (2 bytes) + raw submission.
  bstring signed0;
  EXPECT_TRUE(entry0->SerializeSigned(&signed0));
  EXPECT_TRUE(signed0.substr(2) == kUnicorn || signed0.substr(2) == kAlice);
  log_segment_tree.AddLeaf(signed0);

  EXPECT_EQ(this->tree_logger_->EntryInfo(0, 1, &result1), LogDB::LOGGED);
  LogEntry *entry1 = LogEntry::Deserialize(result1);
  ASSERT_TRUE(entry1 != NULL);
  EXPECT_EQ(entry1->Type(), LogEntry::TEST_ENTRY);

  bstring signed1;
  EXPECT_TRUE(entry1->SerializeSigned(&signed1));
  EXPECT_TRUE(signed0.substr(2) == kUnicorn || signed0.substr(2) == kAlice);

  EXPECT_NE(signed0, signed1);
  log_segment_tree.AddLeaf(signed1);
  delete entry0;
  delete entry1;
  data.log_segment.tree_data.root = log_segment_tree.CurrentRoot();

  MerkleTree segment_info_tree(new Sha256Hasher());
  segment_info_tree.AddLeaf(data.log_segment.tree_data.Serialize());
  data.log_head.tree_data.root = segment_info_tree.CurrentRoot();

  // Verify the signatures.
  EXPECT_EQ(data.log_segment.tree_data.sequence_number, 0U);
  EXPECT_EQ(data.log_segment.tree_data.segment_size, 2U);
  EXPECT_TRUE(this->verifier_->VerifyLogSegmentSignature(data.log_segment));
  EXPECT_TRUE(this->verifier_->VerifySegmentInfoSignature(data.log_head));

  SegmentData wrong_data = data;

  // Various invalid signatures.
  ++wrong_data.log_segment.tree_data.segment_size;
  EXPECT_FALSE(this->verifier_->VerifyLogSegmentSignature(wrong_data.log_segment));
  --wrong_data.log_segment.tree_data.segment_size;

  ++wrong_data.log_segment.tree_data.sequence_number;
  ++wrong_data.log_head.tree_data.sequence_number;
  EXPECT_FALSE(this->verifier_->VerifyLogSegmentSignature(wrong_data.log_segment));
  EXPECT_FALSE(this->verifier_->VerifySegmentInfoSignature(wrong_data.log_head));
  ++wrong_data.log_segment.tree_data.sequence_number;
  ++wrong_data.log_head.tree_data.sequence_number;

  wrong_data.log_segment.tree_data.root = data.log_head.tree_data.root;
  wrong_data.log_head.tree_data.root = data.log_segment.tree_data.root;
  EXPECT_FALSE(this->verifier_->VerifyLogSegmentSignature(wrong_data.log_segment));
  EXPECT_FALSE(this->verifier_->VerifySegmentInfoSignature(wrong_data.log_head));
  wrong_data.log_segment.tree_data.root = data.log_segment.tree_data.root;
  wrong_data.log_head.tree_data.root = data.log_head.tree_data.root;

  wrong_data.log_segment.signature = data.log_head.signature;
  wrong_data.log_head.signature = data.log_head.signature;
  EXPECT_FALSE(this->verifier_->VerifyLogSegmentSignature(wrong_data.log_segment));
  EXPECT_FALSE(this->verifier_->VerifySegmentInfoSignature(wrong_data.log_head));
}

TYPED_TEST(TreeLoggerTest, AuditProof) {
  const bstring kUnicorn(unicorn, 7);
  const bstring kAlice(alice, 5);
  bstring key0, key1;

  this->tree_logger_->QueueEntry(kUnicorn, &key0);
  this->tree_logger_->QueueEntry(kAlice, &key1);
  this->tree_logger_->LogSegment();

  bstring segment;
  EXPECT_EQ(this->tree_logger_->SegmentInfo(0, &segment), LogDB::LOGGED);
  EXPECT_FALSE(segment.empty());

  SegmentData data;
  EXPECT_TRUE(data.DeserializeSegmentInfo(segment));

  // Query an audit proof, and verify it.
  EXPECT_FALSE(key0.empty());
  bstring result0, result1, signed0, signed1;
  AuditProof proof0, proof1;
  EXPECT_EQ(this->tree_logger_->EntryInfo(key0, LogDB::LOGGED_ONLY, &result0),
            LogDB::LOGGED);
  EXPECT_EQ(this->tree_logger_->EntryAuditProof(key0, &proof0), LogDB::LOGGED);

  LogEntry *entry0 = LogEntry::Deserialize(result0);
  ASSERT_TRUE(entry0 != NULL);
  EXPECT_TRUE(entry0->SerializeSigned(&signed0));

  EXPECT_EQ(this->verifier_->VerifyLogSegmentAuditProof(proof0, signed0),
            LogVerifier::VERIFY_OK);

  EXPECT_FALSE(key1.empty());
  EXPECT_EQ(this->tree_logger_->EntryInfo(key1, LogDB::LOGGED_ONLY, &result1),
            LogDB::LOGGED);

  LogEntry *entry1 = LogEntry::Deserialize(result1);
  ASSERT_TRUE(entry1 != NULL);
  EXPECT_TRUE(entry1->SerializeSigned(&signed1));
  EXPECT_EQ(this->tree_logger_->EntryAuditProof(key1, &proof1), LogDB::LOGGED);

  EXPECT_EQ(this->verifier_->VerifyLogSegmentAuditProof(proof1, signed1),
         LogVerifier::VERIFY_OK);

  delete entry0;
  delete entry1;

  // Some invalid proofs.
  EXPECT_NE(this->verifier_->VerifyLogSegmentAuditProof(proof0, signed1),
         LogVerifier::VERIFY_OK);
  EXPECT_NE(this->verifier_->VerifyLogSegmentAuditProof(proof1, signed0),
         LogVerifier::VERIFY_OK);

  AuditProof wrong_proof = proof0;
  // Not wrong yet...
  EXPECT_EQ(this->verifier_->VerifyLogSegmentAuditProof(wrong_proof, signed0),
         LogVerifier::VERIFY_OK);
  // Wrong sequence number.
  ++wrong_proof.sequence_number;
  EXPECT_NE(this->verifier_->VerifyLogSegmentAuditProof(wrong_proof, signed0),
         LogVerifier::VERIFY_OK);
  --wrong_proof.sequence_number;
  // Wrong tree size.
  ++wrong_proof.tree_size;
  EXPECT_NE(this->verifier_->VerifyLogSegmentAuditProof(wrong_proof, signed0),
         LogVerifier::VERIFY_OK);
  --wrong_proof.tree_size;
  // Wrong leaf index.
  ++wrong_proof.leaf_index;
  EXPECT_NE(this->verifier_->VerifyLogSegmentAuditProof(wrong_proof, signed0),
         LogVerifier::VERIFY_OK);
  --wrong_proof.leaf_index;
  // Wrong signature.
  wrong_proof.signature = data.log_head.signature;
  EXPECT_NE(this->verifier_->VerifyLogSegmentAuditProof(wrong_proof, signed0),
         LogVerifier::VERIFY_OK);
  wrong_proof.signature = proof0.signature;
  // Wrong audit path.
  wrong_proof.audit_path = proof1.audit_path;
  EXPECT_NE(this->verifier_->VerifyLogSegmentAuditProof(wrong_proof, signed0),
         LogVerifier::VERIFY_OK);
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
