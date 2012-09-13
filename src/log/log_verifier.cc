#include <stdint.h>

#include "ct.pb.h"
#include "log_signer.h"
#include "log_verifier.h"
#include "merkle_verifier.h"
#include "serializer.h"
#include "submission_handler.h"
#include "util.h"

using ct::SignedCertificateTimestamp;

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
  bstring signed_part, signed_part2;

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

bool LogVerifier::IsBetween(uint64_t timestamp, uint64_t earliest,
                            uint64_t latest) const {
  return timestamp >= earliest && timestamp <= latest;
}
