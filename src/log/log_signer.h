#ifndef LOG_SIGNER_H
#define LOG_SIGNER_H

#include <openssl/evp.h>

#include "../include/types.h"
#include "../merkletree/LogRecord.h"
#include "../util/util.h"

class LogSigner {
 public:
  LogSigner(EVP_PKEY *pkey);
  ~LogSigner();

  // One byte.
  // Each struct we digitally sign has a unique type identifier.
  enum SignatureType {
    LOG_SEGMENT = 0,
    LOG_HEAD = 1,
  };

  DigitallySigned SignLogSegment(const LogSegmentTreeData &data) const {
    return Sign(LOG_SEGMENT, data);
  }

  DigitallySigned SignLogHead(const LogHeadTreeData &data) const {
    return Sign(LOG_HEAD, data);
  }

 private:
  // T must have a Serialize() method.
  template<class T>
  DigitallySigned Sign(SignatureType type, const T &input) const {
    bstring to_be_signed = util::SerializeUint(type, 1);
    to_be_signed.append(input.Serialize());

    DigitallySigned digitally_signed;
    digitally_signed.hash_algo = hash_algo_;
    digitally_signed.sig_algo = sig_algo_;
    digitally_signed.sig_string = Sign(to_be_signed);
    return digitally_signed;
  }

  bstring Sign(const bstring &data) const;

  EVP_PKEY *pkey_;
  DigitallySigned::HashAlgorithm hash_algo_;
  DigitallySigned::SignatureAlgorithm sig_algo_;
};

class LogSigVerifier {
 public:
  LogSigVerifier(EVP_PKEY *pkey);
  ~LogSigVerifier();

  bool
  VerifyLogSegmentSignature(const LogSegmentCheckpoint &checkpoint) const {
    return Verify(LogSigner::LOG_SEGMENT, checkpoint.tree_data,
                  checkpoint.signature);
  }

  bool VerifySegmentInfoSignature(const LogHeadCheckpoint &checkpoint) const {
    return Verify(LogSigner::LOG_HEAD, checkpoint.tree_data,
                  checkpoint.signature);
  }

 private:
  // T must have a Serialize() method.
  template<class T>
  bool Verify(LogSigner::SignatureType type, const T &input,
              const DigitallySigned &signature) const {
    if (signature.hash_algo != hash_algo_ || signature.sig_algo != sig_algo_)
      return false;
    bstring to_be_signed = util::SerializeUint(type, 1);
    to_be_signed.append(input.Serialize());
    return Verify(to_be_signed, signature.sig_string);
  }

  bool Verify(const bstring &data, const bstring &sig_string) const;

  EVP_PKEY *pkey_;
  DigitallySigned::HashAlgorithm hash_algo_;
  DigitallySigned::SignatureAlgorithm sig_algo_;
};
#endif
