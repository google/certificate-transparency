#include <assert.h>

#include "../include/types.h"
#include "../log/log_signer.h"
#include "LogRecord.h"
#include "LogVerifier.h"
#include "MerkleVerifier.h"
#include "SerialHasher.h"

LogVerifier::LogVerifier(LogSigVerifier *sig_verifier)
  : sig_verifier_(sig_verifier),
    tree_verifier_(new Sha256Hasher()) {
  assert(sig_verifier_ != NULL);
}

LogVerifier::~LogVerifier() {
  delete sig_verifier_;
}

// static
LogVerifier::VerifyResult
LogVerifier::LogSegmentTreeDataConsistency(const LogSegmentTreeData &a,
                                           const LogSegmentTreeData &b) {
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
  assert(audit_proof.proof_type == AuditProof::LOG_SEGMENT_PROOF);
  bstring root = tree_verifier_.RootFromPath(audit_proof.leaf_index + 1,
                                             audit_proof.tree_size,
                                             audit_proof.audit_path, leaf);
  if (root.empty())
    return LogVerifier::INVALID_PATH;
  assert(root.size() == 32);

  LogSegmentCheckpoint local;
  local.tree_data.sequence_number = audit_proof.sequence_number;
  local.tree_data.segment_size = audit_proof.tree_size;
  local.tree_data.root = root;
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
  assert(audit_proof.proof_type == AuditProof::LOG_HEAD_PROOF);
  bstring leaf = data.tree_data.Serialize();
  bstring root = tree_verifier_.RootFromPath(audit_proof.leaf_index + 1,
                                             audit_proof.tree_size,
                                             audit_proof.audit_path, leaf);
  if (root.empty())
    return LogVerifier::INVALID_PATH;
  assert(root.size() == 32);
  LogHeadCheckpoint local;
  local.tree_data.sequence_number = audit_proof.sequence_number;
  local.tree_data.root = root;
  local.signature = audit_proof.signature;
  if (!VerifySegmentInfoSignature(local))
    return LogVerifier::INVALID_SIGNATURE;
  if (checkpoint != NULL)
    *checkpoint = local;
  return LogVerifier::VERIFY_OK;
}
