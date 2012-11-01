#include <stdint.h>

#include "log/cert_submission_handler.h"
#include "log/log_signer.h"
#include "log/log_verifier.h"
#include "merkletree/merkle_verifier.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"
#include "util/util.h"

using ct::LogEntry;
using ct::MerkleAuditProof;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;
using std::string;

LogVerifier::LogVerifier(LogSigVerifier *sig_verifier,
                         MerkleVerifier *tree_verifier)
    : sig_verifier_(sig_verifier),
      tree_verifier_(tree_verifier) {}

LogVerifier::~LogVerifier() {
  delete sig_verifier_;
  delete tree_verifier_;
}

LogVerifier::VerifyResult LogVerifier::VerifySignedCertificateTimestamp(
    const LogEntry &entry, const SignedCertificateTimestamp &sct,
    uint64_t begin_range, uint64_t end_range) const {
  if (!IsBetween(sct.timestamp(), begin_range, end_range))
    return INVALID_TIMESTAMP;

  // TODO(ekasper): separate format and signature errors.
  if (sig_verifier_->VerifySCTSignature(entry, sct) != LogSigVerifier::OK)
    return INVALID_SIGNATURE;
  return VERIFY_OK;
}

LogVerifier::VerifyResult LogVerifier::VerifySignedCertificateTimestamp(
    const LogEntry &entry, const SignedCertificateTimestamp &sct) const {
  // Allow a bit of slack, say 1 second into the future.
  return VerifySignedCertificateTimestamp(entry, sct, 0,
                                          util::TimeInMilliseconds() + 1000);
}

LogVerifier::VerifyResult
LogVerifier::VerifySignedTreeHead(const SignedTreeHead &sth,
                                  uint64_t begin_range,
                                  uint64_t end_range) const {
  if (!IsBetween(sth.timestamp(), begin_range, end_range))
    return INVALID_TIMESTAMP;

  if (sig_verifier_->VerifySTHSignature(sth) != LogSigVerifier::OK)
    return INVALID_SIGNATURE;
  return VERIFY_OK;
}

LogVerifier::VerifyResult LogVerifier::VerifySignedTreeHead(
    const SignedTreeHead &sth) const {
  // Allow a bit of slack, say 1 second into the future.
  return VerifySignedTreeHead(sth, 0, util::TimeInMilliseconds() + 1000);
}

LogVerifier::VerifyResult
LogVerifier::VerifyMerkleAuditProof(const LogEntry &entry,
                                    const SignedCertificateTimestamp &sct,
                                    const MerkleAuditProof &merkle_proof)
    const {
  if (!IsBetween(merkle_proof.timestamp(), sct.timestamp(),
                 util::TimeInMilliseconds() + 1000))
    return INCONSISTENT_TIMESTAMPS;

  string serialized_leaf;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeSCTMerkleTreeLeaf(sct, entry, &serialized_leaf);

  if (serialize_result != Serializer::OK)
    return INVALID_FORMAT;

  std::vector<string> path;
  for (int i = 0; i < merkle_proof.path_node_size(); ++i)
    path.push_back(merkle_proof.path_node(i));

  // Leaf indexing in the MerkleTree starts from 1.
  string root_hash =
      tree_verifier_->RootFromPath(merkle_proof.leaf_index() + 1,
                                   merkle_proof.tree_size(), path,
                                   serialized_leaf);

  if (root_hash.empty())
    return INVALID_MERKLE_PATH;

  SignedTreeHead sth;
  sth.set_version(merkle_proof.version());
  sth.mutable_id()->CopyFrom(merkle_proof.id());
  sth.set_timestamp(merkle_proof.timestamp());
  sth.set_tree_size(merkle_proof.tree_size());
  sth.set_root_hash(root_hash);
  sth.mutable_signature()->CopyFrom(merkle_proof.tree_head_signature());

  if (sig_verifier_->VerifySTHSignature(sth) != LogSigVerifier::OK)
    return INVALID_SIGNATURE;
  return VERIFY_OK;
}

bool LogVerifier::IsBetween(uint64_t timestamp, uint64_t earliest,
                            uint64_t latest) const {
  return timestamp >= earliest && timestamp <= latest;
}
