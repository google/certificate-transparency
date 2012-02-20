#ifndef LOGVERIFIER_H
#define LOGVERIFIER_H
#include <string>

#include <stddef.h>

#include <openssl/evp.h>

#include "LogRecord.h"
#include "MerkleVerifier.h"

class SerialHasher;

class LogVerifier {
 public:
  LogVerifier(EVP_PKEY *pkey);
  ~LogVerifier();

  // Compute the Merkle root from AuditProof.audit_path and
  // verify the signature on the segment data.
  bool VerifyLogSegmentAuditProof(const AuditProof &audit_proof,
                                  const std::string &leaf);
  // Caller is responsible for ensuring that the segment data fields
  // have valid format.
  bool VerifyLogSegmentSignature(const SegmentData &data);

  // Caller is responsible for ensuring that the segment data fields
  // have valid format.
  bool VerifySegmentInfoSignature(const SegmentData &data);

 private:
  EVP_PKEY *pkey_;
  MerkleVerifier verifier_;

  bool VerifySignature(const std::string &data, const std::string &signature);
};
#endif
