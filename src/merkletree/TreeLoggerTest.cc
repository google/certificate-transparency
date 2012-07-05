#include <assert.h>
#include <iostream>
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

void LogVerifierTest(LogDB *db) {
  const unsigned char unicorn[] = "Unicorn";
  const bstring kUnicorn(unicorn, 7);
  const unsigned char alice[] = "Alice";
  const bstring kAlice(alice, 5);

  EVP_PKEY *pkey = PrivateKeyFromPem(ecp256_private_key);
  EVP_PKEY *pubkey = PublicKeyFromPem(ecp256_public_key);
  TreeLogger treelogger(db, new LogSigner(pkey));
  LogVerifier verifier(new LogSigVerifier(pubkey));
  bstring key0, key1;
  assert(treelogger.QueueEntry(kUnicorn, &key0) == LogDB::NEW);
  assert(treelogger.QueueEntry(kAlice, &key1) == LogDB::NEW);
  treelogger.LogSegment();
  bstring segment;
  assert(treelogger.SegmentInfo(0, &segment) == LogDB::LOGGED);
  assert(!segment.empty());
  std::cout << "Segment info:\n" << util::HexString(segment, ' ') << '\n';
  SegmentData data;
  assert(data.DeserializeSegmentInfo(segment));

  // Construct the trees.
  // (TODO: a monitor that can do this automatically.)
  MerkleTree log_segment_tree(new Sha256Hasher());
  bstring result0, result1;

  assert(treelogger.EntryInfo(0, 0, &result0) == LogDB::LOGGED);
  LogEntry *entry0 = LogEntry::Deserialize(result0);
  assert(entry0 != NULL);
  assert(entry0->Type() == LogEntry::TEST_ENTRY);

  // Default submission handling signs the type (2 bytes) + raw submission.
  bstring signed0;
  assert(entry0->SerializeSigned(&signed0));
  assert(signed0.substr(2) == kUnicorn || signed0.substr(2) == kAlice);
  log_segment_tree.AddLeaf(signed0);

  assert(treelogger.EntryInfo(0, 1, &result1) == LogDB::LOGGED);
  LogEntry *entry1 = LogEntry::Deserialize(result1);
  assert(entry1 != NULL);
  assert(entry1->Type() == LogEntry::TEST_ENTRY);

  bstring signed1;
  assert(entry1->SerializeSigned(&signed1));
  assert(signed0.substr(2) == kUnicorn || signed0.substr(2) == kAlice);

  assert(signed0 != signed1);
  log_segment_tree.AddLeaf(signed1);
  delete entry0;
  delete entry1;
  data.log_segment.tree_data.root = log_segment_tree.CurrentRoot();

  MerkleTree segment_info_tree(new Sha256Hasher());
  segment_info_tree.AddLeaf(data.log_segment.tree_data.Serialize());
  data.log_head.tree_data.root = segment_info_tree.CurrentRoot();

  // Verify the signatures.
  assert(data.log_segment.tree_data.sequence_number == 0);
  assert(data.log_segment.tree_data.segment_size == 2);
  assert(verifier.VerifyLogSegmentSignature(data.log_segment));
  assert(verifier.VerifySegmentInfoSignature(data.log_head));

  SegmentData wrong_data = data;

  // Various invalid signatures.
  ++wrong_data.log_segment.tree_data.segment_size;
  assert(!verifier.VerifyLogSegmentSignature(wrong_data.log_segment));
  --wrong_data.log_segment.tree_data.segment_size;

  ++wrong_data.log_segment.tree_data.sequence_number;
  ++wrong_data.log_head.tree_data.sequence_number;
  assert(!verifier.VerifyLogSegmentSignature(wrong_data.log_segment));
  assert(!verifier.VerifySegmentInfoSignature(wrong_data.log_head));
  ++wrong_data.log_segment.tree_data.sequence_number;
  ++wrong_data.log_head.tree_data.sequence_number;

  wrong_data.log_segment.tree_data.root = data.log_head.tree_data.root;
  wrong_data.log_head.tree_data.root = data.log_segment.tree_data.root;
  assert(!verifier.VerifyLogSegmentSignature(wrong_data.log_segment));
  assert(!verifier.VerifySegmentInfoSignature(wrong_data.log_head));
  wrong_data.log_segment.tree_data.root = data.log_segment.tree_data.root;
  wrong_data.log_head.tree_data.root = data.log_head.tree_data.root;

  wrong_data.log_segment.signature = data.log_head.signature;
  wrong_data.log_head.signature = data.log_head.signature;
  assert(!verifier.VerifyLogSegmentSignature(wrong_data.log_segment));
  assert(!verifier.VerifySegmentInfoSignature(wrong_data.log_head));

  // Query an audit proof, and verify it.
  assert(!key0.empty());
  AuditProof proof0, proof1;
  assert(treelogger.EntryInfo(key0, LogDB::LOGGED_ONLY, &result0)
         == LogDB::LOGGED);
  assert(treelogger.EntryAuditProof(key0, &proof0) == LogDB::LOGGED);

  entry0 = LogEntry::Deserialize(result0);
  assert(entry0 != NULL);
  assert(entry0->SerializeSigned(&signed0));

  assert(verifier.VerifyLogSegmentAuditProof(proof0, signed0) ==
         LogVerifier::VERIFY_OK);

  assert(!key1.empty());
  assert(treelogger.EntryInfo(key1, LogDB::LOGGED_ONLY, &result1)
         == LogDB::LOGGED);

  entry1 = LogEntry::Deserialize(result1);
  assert(entry1 != NULL);
  assert(entry1->SerializeSigned(&signed1));
  assert(treelogger.EntryAuditProof(key1, &proof1) == LogDB::LOGGED);

  assert(verifier.VerifyLogSegmentAuditProof(proof1, signed1) ==
         LogVerifier::VERIFY_OK);

  delete entry0;
  delete entry1;

  // Some invalid proofs.
  assert(verifier.VerifyLogSegmentAuditProof(proof0, signed1) !=
         LogVerifier::VERIFY_OK);
  assert(verifier.VerifyLogSegmentAuditProof(proof1, signed0) !=
         LogVerifier::VERIFY_OK);

  AuditProof wrong_proof = proof0;
  // Not wrong yet...
  assert(verifier.VerifyLogSegmentAuditProof(wrong_proof, signed0) ==
         LogVerifier::VERIFY_OK);
  // Wrong sequence number.
  ++wrong_proof.sequence_number;
  assert(verifier.VerifyLogSegmentAuditProof(wrong_proof, signed0) !=
         LogVerifier::VERIFY_OK);
  --wrong_proof.sequence_number;
  // Wrong tree size.
  ++wrong_proof.tree_size;
  assert(verifier.VerifyLogSegmentAuditProof(wrong_proof, signed0) !=
         LogVerifier::VERIFY_OK);
  --wrong_proof.tree_size;
  // Wrong leaf index.
  ++wrong_proof.leaf_index;
  assert(verifier.VerifyLogSegmentAuditProof(wrong_proof, signed0) !=
         LogVerifier::VERIFY_OK);
  --wrong_proof.leaf_index;
  // Wrong signature.
  wrong_proof.signature = data.log_head.signature;
  assert(verifier.VerifyLogSegmentAuditProof(wrong_proof, signed0) !=
         LogVerifier::VERIFY_OK);
  wrong_proof.signature = proof0.signature;
  // Wrong audit path.
  wrong_proof.audit_path = proof1.audit_path;
  assert(verifier.VerifyLogSegmentAuditProof(wrong_proof, signed0) !=
         LogVerifier::VERIFY_OK);
}

void MemoryLoggerTest() {
  LogVerifierTest(new MemoryDB());
}

void FileLoggerTest() {
  // Create a new directory for testing.
  assert(mkdir("/tmp/ct/b", 0777) == 0);
  FileDB *db = new FileDB("/tmp/ct/b", 5);
  db->Init();
  LogVerifierTest(db);
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
