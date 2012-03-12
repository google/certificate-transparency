#include <assert.h>
#include <iostream>
#include <stddef.h>
#include <string>

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

void AnyLoggerTest(LogDB *log) {
  EVP_PKEY *pkey = PrivateKeyFromPem(ecp256_private_key);
  TreeLogger treelogger(log, pkey);
  std::string key0, key1, key2, key3, value0, value1, value2, value3,
    segment0, segment1;
  assert(treelogger.QueueEntry("Unicorn", &key0) == LogDB::NEW);
  assert(treelogger.QueueEntry("Alice", &key1) == LogDB::NEW);

  // Count with and without pending entries.
  //assert(treelogger.LoggedLogSize() == 0);
  assert(treelogger.PendingLogSize() == 2);

  // Try to enter a duplicate.
  assert(treelogger.QueueEntry("Unicorn", &key2) == LogDB::PENDING);
  assert(key0 == key2);
  //assert(treelogger.LoggedLogSize() == 0);
  assert(treelogger.PendingLogSize() == 2);

  // Look up pending entries.
  assert(treelogger.SegmentCount() == 0);
  //assert(treelogger.EntryInfo(0, LogDB::ANY, &value0) == LogDB::PENDING);
  //assert(value0 == "Unicorn");
  // FIXME: MemoryDB needs fixing
  //assert(treelogger.EntryInfo(0, 1, LogDB::ANY, NULL) == LogDB::NOT_FOUND);
  assert(treelogger.EntryInfo(key1, LogDB::LOGGED_ONLY, &value1)
         == LogDB::PENDING);
  assert(value1.empty());
  assert(treelogger.EntryInfo(key1, LogDB::PENDING_ONLY, &value1)
         == LogDB::PENDING);
  assert(value1 == "Alice");

  // Look up missing entries.
  //assert(treelogger.EntryInfo(2, LogDB::ANY, NULL) == LogDB::NOT_FOUND);
  assert(treelogger.EntryInfo(1, 0, LogDB::ANY, &value2) == LogDB::NOT_FOUND);
  assert(value2.empty());

  // Look up missing segment info.
  // FIXME: should be NOT_FOUND?
  //  assert(treelogger.SegmentInfo(0, NULL) == LogDB::PENDING);
  assert(treelogger.SegmentInfo(1, NULL) == LogDB::NOT_FOUND);
  //assert(treelogger.SegmentInfo(0, &segment0) == LogDB::PENDING);
  //assert(segment0.empty());

  // Log the first segment.
  treelogger.LogSegment();
  //assert(treelogger.LoggedLogSize() == 2);
  assert(treelogger.PendingLogSize() == 0);
  assert(treelogger.SegmentCount() == 1);
  assert(treelogger.SegmentInfo(0, &segment0) == LogDB::LOGGED);
  assert(!segment0.empty());
  std::cout << HexString(segment0) << '\n';

  value0.clear();
  value1.clear();
  value2.clear();

  // Look up logged entries.
  //assert(treelogger.EntryInfo(0, LogDB::LOGGED_ONLY, &value0) == LogDB::LOGGED);
  //assert(value0 == "Unicorn");
  assert(treelogger.EntryInfo(0, 1, LogDB::ANY, &value1) == LogDB::LOGGED);
  assert(value1 == "Alice");
  assert(treelogger.EntryInfo(key0, LogDB::PENDING_ONLY, &value2)
         == LogDB::LOGGED);
  assert(value2.empty());
  assert(treelogger.EntryInfo(key0, LogDB::ANY, &value2) == LogDB::LOGGED);
  assert(value2 == "Unicorn");

  // Look up missing entries.
  assert(treelogger.EntryInfo(0, 2, LogDB::ANY, NULL) == LogDB::NOT_FOUND);
  assert(treelogger.EntryInfo(1, 0, LogDB::ANY, NULL) == LogDB::NOT_FOUND);
  assert(treelogger.EntryInfo(key3, LogDB::ANY, NULL) == LogDB::NOT_FOUND);
  key3 = "RogueKey";
  assert(treelogger.EntryInfo(key3, LogDB::ANY, &value3) == LogDB::NOT_FOUND);
  assert(value3.empty());

  // Queue another entry and look it up.
  assert(treelogger.QueueEntry("Banana", &key3) == LogDB::NEW);
  assert(treelogger.SegmentCount() == 1);
  //assert(treelogger.EntryInfo(2, LogDB::PENDING_ONLY, &value3)
  //       == LogDB::PENDING);
  //assert(value3 == "Banana");
  // FIXME: MemoryDB needs fixing
  //assert(treelogger.EntryInfo(1, 0, LogDB::ANY, NULL) == LogDB::NOT_FOUND);
  value3.clear();
  assert(treelogger.EntryInfo(key3, LogDB::ANY, &value3) == LogDB::PENDING);
  assert(value3 == "Banana");

  // Log the segment.
  //assert(treelogger.LoggedLogSize() == 2);
  assert(treelogger.PendingLogSize() == 1);
  treelogger.LogSegment();
  //assert(treelogger.LoggedLogSize() == 3);
  assert(treelogger.PendingLogSize() == 0);
  assert(treelogger.SegmentCount() == 2);
  assert(treelogger.SegmentInfo(1, &segment1) == LogDB::LOGGED);
  assert(segment0 != segment1);
  std::cout << HexString(segment1) << '\n';

  // Look up the logged entry.
  //assert(treelogger.EntryInfo(2, LogDB::ANY, NULL) == LogDB::LOGGED);
  value3.clear();
  assert(treelogger.EntryInfo(1, 0, LogDB::LOGGED_ONLY, &value3)
         == LogDB::LOGGED);
  assert(value3 == "Banana");
  value3.clear();
  assert(treelogger.EntryInfo(key3, LogDB::ANY, &value3) == LogDB::LOGGED);
  assert(value3 == "Banana");

  // More missing data.
  assert(treelogger.EntryInfo(1, 1, LogDB::ANY, NULL) == LogDB::NOT_FOUND);

  //FIXME: MemoryDB needs fixing...
  //assert(treelogger.SegmentInfo(2, NULL) == LogDB::NOT_FOUND);
  assert(treelogger.SegmentInfo(3, NULL) == LogDB::NOT_FOUND);
}

void LogVerifierTest() {
  EVP_PKEY *pkey = PrivateKeyFromPem(ecp256_private_key);
  EVP_PKEY *pubkey = PublicKeyFromPem(ecp256_public_key);
  TreeLogger treelogger(new MemoryDB(), pkey);
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
  log_segment_tree.AddLeaf("Unicorn");
  log_segment_tree.AddLeaf("Alice");
  data.segment_root = log_segment_tree.CurrentRoot();

  MerkleTree segment_info_tree(new Sha256Hasher());
  segment_info_tree.AddLeaf(data.segment_sig.signature);
  data.segment_info_root = segment_info_tree.CurrentRoot();

  // Verify the signatures.
  assert(data.sequence_number == 0);
  assert(data.segment_size == 2);
  assert(verifier.VerifyLogSegmentSignature(data));
  assert(verifier.VerifySegmentInfoSignature(data));

  SegmentData wrong_data = data;

  // Various invalid signatures.
  ++wrong_data.segment_size;
  assert(!verifier.VerifyLogSegmentSignature(wrong_data));
  --wrong_data.segment_size;

  ++wrong_data.sequence_number;
  assert(!verifier.VerifyLogSegmentSignature(wrong_data));
  assert(!verifier.VerifySegmentInfoSignature(wrong_data));
  --wrong_data.sequence_number;

  wrong_data.segment_root = data.segment_info_root;
  wrong_data.segment_info_root = data.segment_root;
  assert(!verifier.VerifyLogSegmentSignature(wrong_data));
  assert(!verifier.VerifySegmentInfoSignature(wrong_data));
  wrong_data.segment_root = data.segment_root;
  wrong_data.segment_info_root = data.segment_info_root;

  wrong_data.segment_sig = data.segment_info_sig;
  wrong_data.segment_info_sig = data.segment_sig;
  assert(!verifier.VerifyLogSegmentSignature(wrong_data));
  assert(!verifier.VerifySegmentInfoSignature(wrong_data));

  // Query an audit proof, and verify it.
  assert(!key0.empty());
  AuditProof proof0, proof1;
  assert(treelogger.EntryAuditProof(key0, &proof0) == LogDB::LOGGED);
  assert(verifier.VerifyLogSegmentAuditProof(proof0, "Unicorn"));
  assert(!key1.empty());
  assert(treelogger.EntryAuditProof(key1, &proof1) == LogDB::LOGGED);
  assert(verifier.VerifyLogSegmentAuditProof(proof1, "Alice"));

  // Some invalid proofs.
  assert(!verifier.VerifyLogSegmentAuditProof(proof0, "Alice"));
  assert(!verifier.VerifyLogSegmentAuditProof(proof1, "Unicorn"));

  AuditProof wrong_proof = proof0;
  // Wrong sequence number.
  ++wrong_proof.sequence_number;
  assert(!verifier.VerifyLogSegmentAuditProof(wrong_proof, "Alice"));
  --wrong_proof.sequence_number;
  // Wrong tree size.
  ++wrong_proof.tree_size;
  assert(!verifier.VerifyLogSegmentAuditProof(wrong_proof, "Alice"));
  --wrong_proof.tree_size;
  // Wrong leaf index.
  ++wrong_proof.leaf_index;
  assert(!verifier.VerifyLogSegmentAuditProof(wrong_proof, "Alice"));
  --wrong_proof.leaf_index;
  // Wrong signature.
  wrong_proof.signature = proof1.signature;
  assert(!verifier.VerifyLogSegmentAuditProof(wrong_proof, "Alice"));
  wrong_proof.signature = proof0.signature;
  // Wrong audit path.
  wrong_proof.audit_path = proof1.audit_path;
  assert(!verifier.VerifyLogSegmentAuditProof(wrong_proof, "Alice"));
}

void MemoryLoggerTest() {
 AnyLoggerTest(new MemoryDB());
}

void FileLoggerTest() {
 AnyLoggerTest(new FileDB("/tmp/ct", 5));
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
  LogVerifierTest();
  std::cout << "PASS\n";
  return 0;
}
