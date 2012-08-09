#ifndef LOG_SIGNER_H
#define LOG_SIGNER_H

#include <openssl/evp.h>

#include "../include/types.h"
#include "../proto/ct.pb.h"

class LogSigner {
 public:
  LogSigner(EVP_PKEY *pkey);
  ~LogSigner();

  // One byte.
  // Each struct we digitally sign has a unique type identifier.
  enum SignatureType {
    CERTIFICATE_HASH = 0,
    TREE_HASH = 1,
  };


  void SignCertificateHash(SignedCertificateHash *sch) const;

 private:
  void Sign(SignatureType type, const bstring &data,
            DigitallySigned *result) const;

  bstring RawSign(const bstring &data) const;

  EVP_PKEY *pkey_;
  DigitallySigned::HashAlgorithm hash_algo_;
  DigitallySigned::SignatureAlgorithm sig_algo_;
};

class LogSigVerifier {
 public:
  LogSigVerifier(EVP_PKEY *pkey);
  ~LogSigVerifier();

  bool VerifyCertificateHashSignature(const SignedCertificateHash &sch) const;

 private:
  bool Verify(LogSigner::SignatureType type, const bstring &input,
              const DigitallySigned &signature) const;

  bool RawVerify(const bstring &data, const bstring &sig_string) const;

  EVP_PKEY *pkey_;
  DigitallySigned::HashAlgorithm hash_algo_;
  DigitallySigned::SignatureAlgorithm sig_algo_;
};
#endif
