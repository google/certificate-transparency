#ifndef LOGVERIFIER_H
#define LOGVERIFIER_H
#include <string>

#include <stddef.h>

#include <openssl/evp.h>

#include "LogRecord.h"

class SerialHasher;

class LogVerifier {
 public:
  LogVerifier(EVP_PKEY *pkey);
  ~LogVerifier();
  // Caller is responsible for ensuring that the segment data fields
  // have valid format.
  bool VerifyLogSegmentSignature(const SegmentData &data);

  // Caller is responsible for ensuring that the segment data fields
  // have valid format.
  bool VerifySegmentInfoSignature(const SegmentData &data);

 private:
  //  MerkleVerifier verifier_;
  EVP_PKEY *pkey_;

  bool VerifySignature(const std::string &data, const std::string &signature);
};
#endif
