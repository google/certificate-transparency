#ifndef LOG_VERIFIER_H
#define LOG_VERIFIER_H

#include <stdint.h>

#include "ct.pb.h"

class LogSigVerifier;
class MerkleVerifier;

// A verifier for verifying signed statements of the log.
class LogVerifier {
 public:
  LogVerifier(LogSigVerifier *sig_verifier,
              MerkleVerifier *tree_verifier);
  ~LogVerifier();

  enum VerifyResult {
    VERIFY_OK,
    // Invalid format
    INVALID_FORMAT,
    // Invalid timestamp
    INVALID_TIMESTAMP,
   // Timestamps differ.
    INCONSISTENT_TIMESTAMPS,
    // The signature does not verify.
    INVALID_SIGNATURE,
  };

  static std::string VerifyResultString(VerifyResult result) {
    switch(result) {
      case VERIFY_OK:
        return "Verify OK.";
      case INVALID_FORMAT:
        return "Invalid format.";
      case INVALID_TIMESTAMP:
        return "Invalid timestamp.";
     case INCONSISTENT_TIMESTAMPS:
        return "Inconsistent timestamps.";
      case INVALID_SIGNATURE:
        return "Invalid signature.";
      default:
        assert(false);
        return "";
    }
  }

  // Verify that the two entries, if equal, also have consistent timestamps.
  static VerifyResult
  VerifySCTConsistency(const SignedCertificateTimestamp &sct,
                       const SignedCertificateTimestamp &sct2);

  // Verify that the timestamp is in the given range,
  // and the signature is valid.
  // Timestamps are given in milliseconds, since January 1, 1970,
  // 00:00 UTC time.
  VerifyResult
  VerifySignedCertificateTimestamp(const SignedCertificateTimestamp &sct,
                                   uint64_t begin_range,
                                   uint64_t end_range) const;

  // Verify that the timestamp is not in the future, and the signature is valid.
  VerifyResult
  VerifySignedCertificateTimestamp(const SignedCertificateTimestamp &sct) const;

 private:
  LogSigVerifier *sig_verifier_;
  MerkleVerifier *tree_verifier_;

  bool IsBetween(uint64_t timestamp, uint64_t earliest, uint64_t latest) const;
};
#endif
