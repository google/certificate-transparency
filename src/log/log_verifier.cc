#include <stdint.h>

#include "cert_submission_handler.h"
#include "ct.pb.h"
#include "log_signer.h"
#include "log_verifier.h"
#include "merkle_verifier.h"
#include "serializer.h"
#include "util.h"

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

// static
LogVerifier::VerifyResult
LogVerifier::VerifySCTConsistency(const SignedCertificateTimestamp &sct,
                                  const SignedCertificateTimestamp &sct2) {
  string signed_part, signed_part2;

  if (Serializer::SerializeSCTForSigning(sct, &signed_part) != Serializer::OK ||
      Serializer::SerializeSCTForSigning(sct2, &signed_part2) != Serializer::OK)
    return INVALID_FORMAT;
  if (signed_part != signed_part2 || sct.timestamp() == sct2.timestamp())
    return VERIFY_OK;
  // Now we have two identical entries with different timestamps.
  // (Caller should check that they both have valid signatures).
  return INCONSISTENT_TIMESTAMPS;
}

LogVerifier::VerifyResult
LogVerifier::VerifySignedCertificateTimestamp(const
                                              SignedCertificateTimestamp &sct,
                                              uint64_t begin_range,
                                              uint64_t end_range) const {
  if (!IsBetween(sct.timestamp(), begin_range, end_range))
    return INVALID_TIMESTAMP;

  if (sig_verifier_->VerifySCTSignature(sct) != LogSigVerifier::OK)
    return INVALID_SIGNATURE;
  return VERIFY_OK;
}

LogVerifier::VerifyResult LogVerifier::VerifySignedCertificateTimestamp(
    const SignedCertificateTimestamp &sct) const {
  // Allow a bit of slack, say 1 second into the future.
  return VerifySignedCertificateTimestamp(sct, 0,
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
LogVerifier::VerifyMerkleAuditProof(const SignedCertificateTimestamp &sct,
                                    const MerkleAuditProof &merkle_proof)
    const {
  if (!IsBetween(merkle_proof.timestamp(), sct.timestamp(),
                 util::TimeInMilliseconds() + 1000))
    return INCONSISTENT_TIMESTAMPS;

  string serialized_sct;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeSCTForTree(sct, &serialized_sct);
  if (serialize_result != Serializer::OK)
    return INVALID_FORMAT;

  std::vector<string> path;
  for (int i = 0; i < merkle_proof.path_node_size(); ++i)
    path.push_back(merkle_proof.path_node(i));

  // Leaf indexing in the MerkleTree starts from 1.
  string root_hash =
      tree_verifier_->RootFromPath(merkle_proof.leaf_index() + 1,
                                   merkle_proof.tree_size(), path,
                                   serialized_sct);

  if (root_hash.empty())
    return INVALID_MERKLE_PATH;

  SignedTreeHead sth;
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
