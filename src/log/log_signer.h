#ifndef LOG_SIGNER_H
#define LOG_SIGNER_H

#include <openssl/evp.h>
#include <openssl/x509.h>  // for i2d_PUBKEY
#include <stdint.h>

#include "ct.h"
#include "ct.pb.h"
#include "serializer.h"

class LogSigner {
 public:
  explicit LogSigner(EVP_PKEY *pkey);
  ~LogSigner();

  std::string KeyID() const { return key_id_; }

  enum SignResult {
    OK,
    INVALID_ENTRY_TYPE,
    EMPTY_CERTIFICATE,
    CERTIFICATE_TOO_LONG,
    INVALID_HASH_LENGTH,
    UNSUPPORTED_VERSION,
    EXTENSIONS_TOO_LONG,
  };

  // The protobuf-agnostic library version:
  // sign the cert timestamp and return the result as a serialized
  // signature string.
  // In accordance with the spec, timestamp should be UTC time,
  // since January 1, 1970, 00:00, in milliseconds.
  SignResult SignV1CertificateTimestamp(
      uint64_t timestamp, ct::LogEntryType type,
      const std::string &leaf_certificate, const std::string &extensions,
      std::string *result) const;

  // Sign the cert timestamp and write the resulting DigitallySigned
  // signature message into |sct|.
  SignResult SignCertificateTimestamp(
      const ct::LogEntry &entry, ct::SignedCertificateTimestamp *sct) const;

  SignResult SignV1TreeHead(uint64_t timestamp, uint64_t tree_size,
                            const std::string &root_hash,
                            std::string *result) const;

  SignResult SignTreeHead(ct::SignedTreeHead *sth) const;

 private:
  static SignResult GetSerializeError(Serializer::SerializeResult result);

  void Sign(const std::string &data, ct::DigitallySigned *result) const;

  std::string RawSign(const std::string &data) const;

  EVP_PKEY *pkey_;
  ct::DigitallySigned::HashAlgorithm hash_algo_;
  ct::DigitallySigned::SignatureAlgorithm sig_algo_;
  std::string key_id_;
};

class LogSigVerifier {
 public:
  explicit LogSigVerifier(EVP_PKEY *pkey);
  ~LogSigVerifier();

  std::string KeyID() const { return key_id_; }

  static std::string ComputeKeyID(EVP_PKEY *pkey);

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
    UNSUPPORTED_VERSION,
    EXTENSIONS_TOO_LONG,
    KEY_ID_MISMATCH,
  };

  // The protobuf-agnostic library version.
  VerifyResult VerifyV1SCTSignature(
      uint64_t timestamp, ct::LogEntryType type, const std::string &leaf_cert,
      const std::string &extensions, const std::string &signature) const;

  VerifyResult VerifySCTSignature(
      const ct::LogEntry &entry,
      const ct::SignedCertificateTimestamp &sct) const;

  // The protobuf-agnostic library version.
  VerifyResult VerifyV1STHSignature(
      uint64_t timestamp, uint64_t tree_size, const std::string &root_hash,
      const std::string &signature) const;

  VerifyResult VerifySTHSignature(const ct::SignedTreeHead &sth) const;

 private:
  static VerifyResult
  GetSerializeError(Serializer::SerializeResult result);

  static VerifyResult
  GetDeserializeSignatureError(Deserializer::DeserializeResult result);

  VerifyResult Verify(const std::string &input,
                      const ct::DigitallySigned &signature) const;

  bool RawVerify(const std::string &data, const std::string &sig_string) const;

  EVP_PKEY *pkey_;
  ct::DigitallySigned::HashAlgorithm hash_algo_;
  ct::DigitallySigned::SignatureAlgorithm sig_algo_;
  std::string key_id_;
};
#endif
