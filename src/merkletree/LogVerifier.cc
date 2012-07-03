#include <assert.h>

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10000000
# error "Need OpenSSL >= 1.0.0"
#endif

#include "../include/types.h"
#include "LogRecord.h"
#include "LogVerifier.h"
#include "MerkleVerifier.h"
#include "SerialHasher.h"

LogVerifier::LogVerifier(EVP_PKEY *pkey) : pkey_(pkey),
                                           verifier_(new Sha256Hasher()) {
  assert(pkey_ != NULL && pkey_->type == EVP_PKEY_EC);
}

LogVerifier::~LogVerifier() {
  EVP_PKEY_free(pkey_);
}

// static
LogVerifier::VerifyResult
LogVerifier::LogSegmentCheckpointConsistency(const LogSegmentCheckpoint &a,
                                             const LogSegmentCheckpoint &b) {
  if (a.sequence_number != b.sequence_number)
    return LogVerifier::VERIFY_OK;
  if (a.segment_size != b.segment_size)
    return LogVerifier::SEGMENT_SIZE_MISMATCH;
  if (a.root != b.root)
    return LogVerifier::ROOT_MISMATCH;
  return LogVerifier::VERIFY_OK;
}

LogVerifier::VerifyResult
LogVerifier::VerifyLogSegmentAuditProof(const AuditProof &audit_proof,
                                        const bstring &leaf) {
  return VerifyLogSegmentAuditProof(audit_proof, leaf, NULL);
}

LogVerifier::VerifyResult
LogVerifier::VerifyLogSegmentAuditProof(const AuditProof &audit_proof,
                                        const bstring &leaf,
                                        LogSegmentCheckpoint *checkpoint) {
  assert(audit_proof.tree_type == SegmentData::LOG_SEGMENT_TREE);
  bstring root = verifier_.RootFromPath(audit_proof.leaf_index + 1,
                                        audit_proof.tree_size,
                                        audit_proof.audit_path, leaf);
  if (root.empty())
    return LogVerifier::INVALID_PATH;
  assert(root.size() == 32);
  LogSegmentCheckpoint local;
  local.sequence_number = audit_proof.sequence_number;
  local.segment_size = audit_proof.tree_size;
  local.root = root;
  local.signature = audit_proof.signature;
  if (!VerifyLogSegmentSignature(local))
    return LogVerifier::INVALID_SIGNATURE;
  if (checkpoint != NULL)
    *checkpoint = local;
  return LogVerifier::VERIFY_OK;
}

LogVerifier::VerifyResult
LogVerifier::VerifySegmentInfoAuditProof(const AuditProof &audit_proof,
                                         const LogSegmentCheckpoint &data) {
  return VerifySegmentInfoAuditProof(audit_proof, data, NULL);
}

LogVerifier::VerifyResult
LogVerifier::VerifySegmentInfoAuditProof(const AuditProof &audit_proof,
                                         const LogSegmentCheckpoint &data,
                                         LogHeadCheckpoint *checkpoint) {
  assert(audit_proof.tree_type == SegmentData::SEGMENT_INFO_TREE);
  bstring leaf = data.SerializeTreeData();
  bstring root = verifier_.RootFromPath(audit_proof.leaf_index + 1,
                                        audit_proof.tree_size,
                                        audit_proof.audit_path, leaf);
  if (root.empty())
    return LogVerifier::INVALID_PATH;
  assert(root.size() == 32);
  LogHeadCheckpoint local;
  local.sequence_number = audit_proof.sequence_number;
  local.root = root;
  local.signature = audit_proof.signature;
  if (!VerifySegmentInfoSignature(local))
    return LogVerifier::INVALID_SIGNATURE;
  if (checkpoint != NULL)
    *checkpoint = local;
  return LogVerifier::VERIFY_OK;
}

bool
LogVerifier::VerifyLogSegmentSignature(const LogSegmentCheckpoint &checkpoint) {
  if (checkpoint.signature.hash_algo != DigitallySigned::SHA256 ||
      checkpoint.signature.sig_algo != DigitallySigned::ECDSA)
    return false;
  bstring in = checkpoint.SerializeTreeData();
  return VerifySignature(in, checkpoint.signature.sig_string);
}

bool LogVerifier::VerifySegmentInfoSignature(const LogHeadCheckpoint
                                             &checkpoint) {
  if (checkpoint.signature.hash_algo != DigitallySigned::SHA256 ||
      checkpoint.signature.sig_algo != DigitallySigned::ECDSA)
    return false;
  bstring in = checkpoint.SerializeTreeData();
  return VerifySignature(in, checkpoint.signature.sig_string);
}

bool LogVerifier::VerifySignature(const bstring &data,
                                  const bstring &signature) {
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);
  // NOTE: this syntax for setting the hash function requires OpenSSL >= 1.0.0.
  assert(EVP_VerifyInit(&ctx, EVP_sha256()) == 1);
  assert(EVP_VerifyUpdate(&ctx, data.data(), data.size()) == 1);
  bool ret =
      (EVP_VerifyFinal(&ctx, signature.data(), signature.size(), pkey_) == 1);
  EVP_MD_CTX_cleanup(&ctx);
  return ret;
}
