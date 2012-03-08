#ifndef LOGVERIFIER_H
#define LOGVERIFIER_H
#include <string>

#include <assert.h>
#include <stddef.h>

#include <openssl/evp.h>

#include "LogRecord.h"
#include "MerkleVerifier.h"

class SerialHasher;

class LogVerifier {
 public:
  LogVerifier(EVP_PKEY *pkey);
  ~LogVerifier();

  enum VerifyResult {
    VERIFY_OK,
    // The proof did not deserialize.
    INVALID_FORMAT,
    // The path does not match the tree size and leaf index.
    INVALID_PATH,
    // The signature does not verify.
    INVALID_SIGNATURE,
    // And finally the REALLY bad cases.
    // The proof is valid but the proof segment size does not match
    // the stored segment size.
    SEGMENT_SIZE_MISMATCH,
    // The proof is valid but the computed root does not match
    // the stored root.
    ROOT_MISMATCH,
  };

  static std::string VerifyResultString(VerifyResult result) {
    switch(result) {
      case VERIFY_OK:
        return "Verify OK.";
      case INVALID_FORMAT:
        return "Invalid format.";
      case INVALID_PATH:
        return "Invalid path.";
      case INVALID_SIGNATURE:
        return "Invalid signature.";
      case SEGMENT_SIZE_MISMATCH:
        return "Segment size mismatch.";
      case ROOT_MISMATCH:
        return "Root mismatch.";
      default:
        assert(false);
        return "";
    }
  }

  // Check whether checkpoints with matching sequence numbers
  // are consistent. (Checkpoints with mismatching sequence numbers
  // are always considered consistent.)
  // NOTE: We do not verify whether the signatures are valid
  // or whether they match (should we?)
  static VerifyResult
  LogSegmentCheckpointConsistency(const LogSegmentCheckpoint &a,
                                  const LogSegmentCheckpoint &b);

  // Compute the Merkle root from AuditProof.audit_path and
  // verify the signature on the segment data.
  VerifyResult VerifyLogSegmentAuditProof(const AuditProof &audit_proof,
                                          const std::string &leaf);

  // Verify the audit proof. Additionally populate the
  // sequence_number, segment_size, segment_root, and segment_sig
  // fields of the segment_data structure from the audit_proof
  // if the proof is valid.
  VerifyResult VerifyLogSegmentAuditProof(const AuditProof &audit_proof,
                                          const std::string &leaf,
                                          LogSegmentCheckpoint *checkpoint);

  // Compute the Merkle root from AuditProof.audit_path and
  // verify the second level signature on the segment info.
  // The LogSegmentCheckpoint has to be partially populated to contain
  // at least the sequence_number, segment_size and segment_root.
  VerifyResult VerifySegmentInfoAuditProof(const AuditProof &audit_proof,
                                           const LogSegmentCheckpoint &data);

  // As above: write a checkpoint.
  VerifyResult VerifySegmentInfoAuditProof(const AuditProof &audit_proof,
                                           const LogSegmentCheckpoint &data,
                                           LogHeadCheckpoint *checkpoint);

  // Caller is responsible for ensuring that the segment checkpoint fields
  // have valid format.
  bool VerifyLogSegmentSignature(const LogSegmentCheckpoint &checkpoint);

  // Caller is responsible for ensuring that the segment checkpoint fields
  // have valid format.
  bool VerifySegmentInfoSignature(const LogHeadCheckpoint &checkpoint);

 private:
  EVP_PKEY *pkey_;
  MerkleVerifier verifier_;

  bool VerifySignature(const std::string &data, const std::string &signature);
};
#endif
