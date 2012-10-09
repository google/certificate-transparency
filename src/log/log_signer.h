#ifndef LOG_SIGNER_H
#define LOG_SIGNER_H

#include <openssl/evp.h>
#include <stdint.h>

#include "ct.pb.h"
#include "serializer.h"

class LogSigner {
 public:
  LogSigner(EVP_PKEY *pkey);
  ~LogSigner();

  // One byte.
  // Each struct we digitally sign has a unique type identifier.
  enum SignatureType {
    CERTIFICATE_TIMESTAMP = 0,
    TREE_HEAD = 1,
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
    INVALID_HASH_LENGTH,
    UNKNOWN_ERROR,
  };

  // The protobuf-agnostic library version:
  // sign the cert timestamp and return the result as a serialized
  // signature string.
  // In accordance with the spec, timestamp should be UTC time,
  // since January 1, 1970, 00:00, in milliseconds.
  SignResult SignCertificateTimestamp(uint64_t timestamp,
                                      CertificateEntryType type,
                                      const std::string &leaf_certificate,
                                      std::string *result) const;

  // Sign the cert timestamp and write the resulting DigitallySigned
  // signature message into |sct|.
  SignResult SignCertificateTimestamp(
      ct::SignedCertificateTimestamp *sct) const;

  SignResult SignTreeHead(uint64_t timestamp, uint64_t tree_size,
                          const std::string &root_hash,
                          std::string *result) const;

  SignResult SignTreeHead(ct::SignedTreeHead *sth) const;

 private:
  static SignResult GetSerializeError(Serializer::SerializeResult result);

  void Sign(SignatureType type, const std::string &data,
            ct::DigitallySigned *result) const;

  std::string RawSign(const std::string &data) const;

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
    INVALID_HASH_LENGTH,
    UNKNOWN_ERROR,
  };

  // The protobuf-agnostic library version.
  VerifyResult VerifySCTSignature(uint64_t timestamp,
                                  LogSigner::CertificateEntryType type,
                                  const std::string &leaf_cert,
                                  const std::string &signature) const;

  VerifyResult VerifySCTSignature(
      const ct::SignedCertificateTimestamp &sct) const;

  // The protobuf-agnostic library version.
  VerifyResult VerifySTHSignature(uint64_t timestamp, uint64_t tree_size,
                                  const std::string &root_hash,
                                  const std::string &signature) const;

  VerifyResult VerifySTHSignature(const ct::SignedTreeHead &sth) const;

 private:
  static VerifyResult
  GetSerializeError(Serializer::SerializeResult result);

  static VerifyResult
  GetDeserializeSignatureError(Deserializer::DeserializeResult result);

  VerifyResult Verify(LogSigner::SignatureType type, const std::string &input,
                      const ct::DigitallySigned &signature) const;

  bool RawVerify(const std::string &data, const std::string &sig_string) const;

  EVP_PKEY *pkey_;
  ct::DigitallySigned::HashAlgorithm hash_algo_;
  ct::DigitallySigned::SignatureAlgorithm sig_algo_;
};
#endif
