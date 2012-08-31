#ifndef LOG_SIGNER_H
#define LOG_SIGNER_H

#include <openssl/evp.h>
#include <stdint.h>

#include "ct.pb.h"
#include "types.h"

class LogSigner {
 public:
  LogSigner(EVP_PKEY *pkey);
  ~LogSigner();

  // One byte.
  // Each struct we digitally sign has a unique type identifier.
  enum SignatureType {
    CERTIFICATE_TIMESTAMP = 0,
    TREE_HASH = 1,
  };

  enum CertificateEntryType {
    X509_ENTRY = 0,
    PRECERT_ENTRY = 1,
  };

  // The protobuf-agnostic library version:
  // sign the cert timestamp and return the result as a serialized
  // signature string.
  // In accordance with the spec, timestamp should be UTC time,
  // since January 1, 1970, 00:00, in milliseconds.
  bool SignCertificateTimestamp(uint64_t timestamp,
                                CertificateEntryType type,
                                const bstring &leaf_certificate,
                                bstring *result) const;

  // Sign the cert timestamp and write the resulting DigitallySigned
  // signature message into |sct|.
  bool SignCertificateTimestamp(SignedCertificateTimestamp *sct) const;

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

  // The protobuf-agnostic library version.
  bool VerifySCTSignature(uint64_t timestamp,
                          LogSigner::CertificateEntryType type,
                          const bstring &leaf_cert,
                          const bstring &signature) const;

  bool VerifySCTSignature(const SignedCertificateTimestamp &sct) const;

 private:
  bool Verify(LogSigner::SignatureType type, const bstring &input,
              const DigitallySigned &signature) const;

  bool RawVerify(const bstring &data, const bstring &sig_string) const;

  EVP_PKEY *pkey_;
  DigitallySigned::HashAlgorithm hash_algo_;
  DigitallySigned::SignatureAlgorithm sig_algo_;
};
#endif
