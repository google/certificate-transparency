#include <iostream>
#include <string>

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

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

static const char *nibble = "0123456789abcdef";

static std::string HexString(const std::string &data) {
  std::string ret;
  for (unsigned int i = 0; i < data.size(); ++i) {
    ret.push_back(nibble[(data[i] >> 4) & 0xf]);
    ret.push_back(nibble[data[i] & 0xf]);
  }
  return ret;
}

void LogVerifierTest(LogDB *db) {
  EVP_PKEY *pkey = PrivateKeyFromPem(ecp256_private_key);
  EVP_PKEY *pubkey = PublicKeyFromPem(ecp256_public_key);
  TreeLogger treelogger(db, pkey);
  LogVerifier verifier(pubkey);
  std::string key0, key1;
  assert(treelogger.QueueEntry("Unicorn", &key0) == LogDB::NEW);
  assert(treelogger.QueueEntry("Alice", &key1) == LogDB::NEW);
  treelogger.LogSegment();
  std::string segment;
  assert(treelogger.SegmentInfo(0, &segment) == LogDB::LOGGED);
  assert(!segment.empty());
  std::cout << HexString(segment) << '\n';
  SegmentData data;
  assert(data.DeserializeSegmentInfo(segment));

  // Construct the trees.
  MerkleTree log_segment_tree(new Sha256Hasher());
  std::string result0, result1;
  assert(treelogger.EntryInfo(0, 0, &result0) == LogDB::LOGGED);
  assert(result0 == "Unicorn" || result0 == "Alice");
  log_segment_tree.AddLeaf(result0);
  assert(treelogger.EntryInfo(0, 1, &result1) == LogDB::LOGGED);
  assert(result1 == "Unicorn" || result1 == "Alice");
  assert(result0 != result1);
  log_segment_tree.AddLeaf(result1);
  data.log_segment.root = log_segment_tree.CurrentRoot();

  MerkleTree segment_info_tree(new Sha256Hasher());
  segment_info_tree.AddLeaf(data.log_segment.SerializeTreeData());
  data.log_head.root = segment_info_tree.CurrentRoot();

  // Verify the signatures.
  assert(data.log_segment.sequence_number == 0);
  assert(data.log_segment.segment_size == 2);
  assert(verifier.VerifyLogSegmentSignature(data.log_segment));
  assert(verifier.VerifySegmentInfoSignature(data.log_head));

  SegmentData wrong_data = data;

  // Various invalid signatures.
  ++wrong_data.log_segment.segment_size;
  assert(!verifier.VerifyLogSegmentSignature(wrong_data.log_segment));
  --wrong_data.log_segment.segment_size;

  ++wrong_data.log_segment.sequence_number;
  ++wrong_data.log_head.sequence_number;
  assert(!verifier.VerifyLogSegmentSignature(wrong_data.log_segment));
  assert(!verifier.VerifySegmentInfoSignature(wrong_data.log_head));
  ++wrong_data.log_segment.sequence_number;
  ++wrong_data.log_head.sequence_number;

  wrong_data.log_segment.root = data.log_head.root;
  wrong_data.log_head.root = data.log_segment.root;
  assert(!verifier.VerifyLogSegmentSignature(wrong_data.log_segment));
  assert(!verifier.VerifySegmentInfoSignature(wrong_data.log_head));
  wrong_data.log_segment.root = data.log_segment.root;
  wrong_data.log_head.root = data.log_head.root;

  wrong_data.log_segment.signature = data.log_head.signature;
  wrong_data.log_head.signature = data.log_head.signature;
  assert(!verifier.VerifyLogSegmentSignature(wrong_data.log_segment));
  assert(!verifier.VerifySegmentInfoSignature(wrong_data.log_head));

  // Query an audit proof, and verify it.
  assert(!key0.empty());
  AuditProof proof0, proof1;
  assert(treelogger.EntryAuditProof(key0, &proof0) == LogDB::LOGGED);
  assert(verifier.VerifyLogSegmentAuditProof(proof0, "Unicorn") ==
         LogVerifier::VERIFY_OK);
  assert(!key1.empty());
  assert(treelogger.EntryAuditProof(key1, &proof1) == LogDB::LOGGED);
  assert(verifier.VerifyLogSegmentAuditProof(proof1, "Alice") ==
         LogVerifier::VERIFY_OK);

  // Some invalid proofs.
  assert(verifier.VerifyLogSegmentAuditProof(proof0, "Alice") !=
         LogVerifier::VERIFY_OK);
  assert(verifier.VerifyLogSegmentAuditProof(proof1, "Unicorn") !=
         LogVerifier::VERIFY_OK);

  AuditProof wrong_proof = proof0;
  // Wrong sequence number.
  ++wrong_proof.sequence_number;
  assert(verifier.VerifyLogSegmentAuditProof(wrong_proof, "Alice") !=
         LogVerifier::VERIFY_OK);
  --wrong_proof.sequence_number;
  // Wrong tree size.
  ++wrong_proof.tree_size;
  assert(verifier.VerifyLogSegmentAuditProof(wrong_proof, "Alice") !=
         LogVerifier::VERIFY_OK);
  --wrong_proof.tree_size;
  // Wrong leaf index.
  ++wrong_proof.leaf_index;
  assert(verifier.VerifyLogSegmentAuditProof(wrong_proof, "Alice") !=
         LogVerifier::VERIFY_OK);
  --wrong_proof.leaf_index;
  // Wrong signature.
  wrong_proof.signature = proof1.signature;
  assert(verifier.VerifyLogSegmentAuditProof(wrong_proof, "Alice") !=
         LogVerifier::VERIFY_OK);
  wrong_proof.signature = proof0.signature;
  // Wrong audit path.
  wrong_proof.audit_path = proof1.audit_path;
  assert(verifier.VerifyLogSegmentAuditProof(wrong_proof, "Alice") !=
         LogVerifier::VERIFY_OK);
}

void MemoryLoggerTest() {
  LogVerifierTest(new MemoryDB());
}

void FileLoggerTest() {
  // Create a new directory for testing.
  assert(mkdir("/tmp/ct/b", 0777) == 0);
  LogVerifierTest(new FileDB("/tmp/ct/b", 5));
  assert(system("rm -r /tmp/ct/b") == 0);
}

} // namespace

int main(int, char**) {
  assert(SSLeay() >= 0x10000000L);
  assert(RAND_status());
  std::cout << "Testing MemoryLogger\n";
  MemoryLoggerTest();
  std::cout << "PASS\n";
  std::cout << "Testing FileLogger\n";
  FileLoggerTest();
  std::cout << "PASS\n";
  std::cout << "Testing LogVerifier\n";
  std::cout << "PASS\n";
  return 0;
}
