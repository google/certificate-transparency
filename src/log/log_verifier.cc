#include <stdint.h>

#include "ct.pb.h"
#include "log_signer.h"
#include "log_verifier.h"
#include "merkle_verifier.h"
#include "serializer.h"
#include "submission_handler.h"
#include "util.h"

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
LogVerifier::VerifySCHConsistency(const SignedCertificateHash &sch,
                                  const SignedCertificateHash &sch2) {
  bstring signed_part, signed_part2;

  if (!Serializer::SerializeForSigning(sch, &signed_part) ||
      !Serializer::SerializeForSigning(sch2, &signed_part2))
    return INVALID_FORMAT;
  if (signed_part != signed_part2 || sch.timestamp() == sch2.timestamp())
    return VERIFY_OK;
  // Now we have two identical entries with different timestamps.
  // (Caller should check that they both have valid signatures).
  return INCONSISTENT_TIMESTAMPS;
}

LogVerifier::VerifyResult
LogVerifier::VerifySignedCertificateHash(const SignedCertificateHash &sch,
                                         uint64_t begin_range,
                                         uint64_t end_range) const {
  if (!IsBetween(sch.timestamp(), begin_range, end_range))
    return INVALID_TIMESTAMP;

  if (!sig_verifier_->VerifyCertificateHashSignature(sch))
    return INVALID_SIGNATURE;
  return VERIFY_OK;
}

LogVerifier::VerifyResult LogVerifier::VerifySignedCertificateHash(
    const SignedCertificateHash &sch) const {
  // Allow a bit of slack, say 1 second into the future.
  return VerifySignedCertificateHash(sch, 0, util::TimeInMilliseconds() + 1000);
}

bool LogVerifier::IsBetween(uint64_t timestamp, uint64_t earliest,
                            uint64_t latest) const {
  return timestamp >= earliest && timestamp <= latest;
}
