#ifndef LOG_SIGNER_H
#define LOG_SIGNER_H

#include <openssl/evp.h>
#include <stdint.h>

#include "ct.pb.h"
#include "serializer.h"
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

  enum SignResult {
    OK,
    INVALID_ENTRY_TYPE,
    EMPTY_CERTIFICATE,
    CERTIFICATE_TOO_LONG,
    UNKNOWN_ERROR,
  };

  // The protobuf-agnostic library version:
  // sign the cert timestamp and return the result as a serialized
  // signature string.
  // In accordance with the spec, timestamp should be UTC time,
  // since January 1, 1970, 00:00, in milliseconds.
  SignResult SignCertificateTimestamp(uint64_t timestamp,
                                      CertificateEntryType type,
                                      const bstring &leaf_certificate,
                                      bstring *result) const;

  // Sign the cert timestamp and write the resulting DigitallySigned
  // signature message into |sct|.
  SignResult SignCertificateTimestamp(
      ct::SignedCertificateTimestamp *sct) const;

 private:
  static SignResult GetSerializeSCTError(Serializer::SerializeResult result);

  void Sign(SignatureType type, const bstring &data,
            ct::DigitallySigned *result) const;

  bstring RawSign(const bstring &data) const;

  EVP_PKEY *pkey_;
  ct::DigitallySigned::HashAlgorithm hash_algo_;
  ct::DigitallySigned::SignatureAlgorithm sig_algo_;
};

class LogSigVerifier {
 public:
  LogSigVerifier(EVP_PKEY *pkey);
  ~LogSigVerifier();

  enum VerifyResult {
    OK,
    INVALID_HASH_ALGORITHM,
    INVALID_SIGNATURE_ALGORITHM,
    SIGNATURE_TOO_SHORT,
    SIGNATURE_TOO_LONG,
    INVALID_ENTRY_TYPE,
    EMPTY_CERTIFICATE,
    CERTIFICATE_TOO_LONG,
    HASH_ALGORITHM_MISMATCH,
    SIGNATURE_ALGORITHM_MISMATCH,
    INVALID_SIGNATURE,
    UNKNOWN_ERROR,
  };

  // The protobuf-agnostic library version.
  VerifyResult VerifySCTSignature(uint64_t timestamp,
                                  LogSigner::CertificateEntryType type,
                                  const bstring &leaf_cert,
                                  const bstring &signature) const;

  VerifyResult VerifySCTSignature(
      const ct::SignedCertificateTimestamp &sct) const;

 private:
  static VerifyResult
  GetSerializeSCTError(Serializer::SerializeResult result);

  static VerifyResult
  GetDeserializeSignatureError(Deserializer::DeserializeResult result);

  VerifyResult Verify(LogSigner::SignatureType type, const bstring &input,
                      const ct::DigitallySigned &signature) const;

  bool RawVerify(const bstring &data, const bstring &sig_string) const;

  EVP_PKEY *pkey_;
  ct::DigitallySigned::HashAlgorithm hash_algo_;
  ct::DigitallySigned::SignatureAlgorithm sig_algo_;
};
#endif
