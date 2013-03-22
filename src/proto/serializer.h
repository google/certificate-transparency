#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <assert.h>
#include <stdint.h>
#include <string>

#include "include/types.h"
#include "proto/ct.pb.h"

// A utility class for writing protocol buffer fields in canonical TLS style.
class Serializer {
 public:
  Serializer() {}
  ~Serializer() {}

  // Serialization methods return OK on success,
  // or the first encountered error on failure.
  enum SerializeResult {
    OK,
    INVALID_ENTRY_TYPE,
    EMPTY_CERTIFICATE,
    CERTIFICATE_TOO_LONG,
    CERTIFICATE_CHAIN_TOO_LONG,
    INVALID_HASH_ALGORITHM,
    INVALID_SIGNATURE_ALGORITHM,
    SIGNATURE_TOO_LONG,
    INVALID_HASH_LENGTH,
    EMPTY_PRECERTIFICATE_CHAIN,
    UNSUPPORTED_VERSION,
    EXTENSIONS_TOO_LONG,
    INVALID_KEYID_LENGTH,
    EMPTY_LIST,
    EMPTY_ELEM_IN_LIST,
    LIST_ELEM_TOO_LONG,
    LIST_TOO_LONG,
  };

  static const size_t kMaxCertificateLength;
  static const size_t kMaxCertificateChainLength;
  static const size_t kMaxSignatureLength;
  static const size_t kMaxExtensionsLength;
  static const size_t kMaxSerializedSCTLength;
  static const size_t kMaxSCTListLength;

  static const size_t kLogEntryTypeLengthInBytes;
  static const size_t kSignatureTypeLengthInBytes;
  static const size_t kHashAlgorithmLengthInBytes;
  static const size_t kSigAlgorithmLengthInBytes;
  static const size_t kVersionLengthInBytes;
  // Log Key ID
  static const size_t kKeyIDLengthInBytes;
  static const size_t kMerkleLeafTypeLengthInBytes;
  // Public key hash from cert
  static const size_t kKeyHashLengthInBytes;

  static size_t PrefixLength(size_t max_length);

  // returns binary data
  std::string SerializedString() const { return output_; }

  static SerializeResult CheckLogEntryFormat(const ct::LogEntry &entry);

  // Helper method to hide some of the ugly select logic.
  static std::string LeafCertificate(const ct::LogEntry &entry);

  static SerializeResult SerializeV1CertSCTSignatureInput(
      uint64_t timestamp, const std::string &certificate,
      const std::string &extensions, std::string *result);

  static SerializeResult SerializeV1PrecertSCTSignatureInput(
      uint64_t timestamp, const std::string &issuer_key_hash,
      const std::string &tbs_certificate,
      const std::string &extensions, std::string *result);

  static SerializeResult SerializeSCTSignatureInput(
      const ct::SignedCertificateTimestamp &sct,
      const ct::LogEntry &entry, std::string *result);

  static SerializeResult SerializeV1CertSCTMerkleTreeLeaf(
      uint64_t timestamp, const std::string &certificate,
      const std::string &extensions, std::string *result);

  static SerializeResult SerializeV1PrecertSCTMerkleTreeLeaf(
      uint64_t timestamp, const std::string &issuer_key_hash,
      const std::string &tbs_certificate,
      const std::string &extensions, std::string *result);

  static SerializeResult
  SerializeSCTMerkleTreeLeaf(const ct::SignedCertificateTimestamp &sct,
                             const ct::LogEntry &entry, std::string *result);

  static SerializeResult SerializeV1STHSignatureInput(
      uint64_t timestamp, uint64_t tree_size,
      const std::string &root_hash, std::string *result);

  static SerializeResult SerializeSTHSignatureInput(
      const ct::SignedTreeHead &sth, std::string *result);

  SerializeResult WriteSCT(const ct::SignedCertificateTimestamp &sct);

  static SerializeResult SerializeSCT(const ct::SignedCertificateTimestamp &sct,
                                      std::string *result);

  static SerializeResult SerializeSCTList(
    const ct::SignedCertificateTimestampList &sct_list, std::string *result);

  // NB This serializes the certificate_chain component of the X509 chain only.
  // Needed for the GetEntries flow.
  static SerializeResult SerializeX509Chain(const ct::X509ChainEntry &entry,
                                            std::string *result);

  static SerializeResult SerializeX509Chain(
      const repeated_string& certificate_chain, std::string *result);

  static SerializeResult SerializePrecertChainEntry(
      const ct::PrecertChainEntry &entry, std::string *result);

  static SerializeResult SerializePrecertChainEntry(
      const std::string &pre_certificate,
      const repeated_string& precertificate_chain,
      std::string *result);


  // TODO(ekasper): tests for these!
  template <class T>
  static std::string SerializeUint(T in, size_t bytes = sizeof(T)) {
    Serializer serializer;
    serializer.WriteUint(in, bytes);
    return serializer.SerializedString();
  }

  static SerializeResult SerializeDigitallySigned(
      const ct::DigitallySigned &sig, std::string *result);

 private:
  template <class T>
  void WriteUint(T in, size_t bytes) {
    assert(bytes <= sizeof in);
    assert(bytes == sizeof in || in >> (bytes * 8) == 0);
    std::string result;
    for ( ; bytes > 0; --bytes)
      output_.push_back(((in & (static_cast<T>(0xff) << ((bytes - 1) * 8)))
           >> ((bytes - 1) * 8)));
  }

  // Fixed-length byte array.
  void WriteFixedBytes(const std::string &in);

  // Variable-length byte array.
  // Caller is responsible for checking |in| <= max_length
  // TODO(ekasper): could return a bool instead.
  void WriteVarBytes(const std::string &in, size_t max_length);

  // Length of the serialized list (with length prefix).
  static size_t SerializedListLength(const repeated_string &in,
                                     size_t max_elem_length,
                                     size_t max_total_length);

  // Serialize (with length prefix).
  // FIXME(ekasper): for simplicity these reject if the list has empty
  // empty elements (all our use cases are like this) but they should take in
  // an arbitrary min bound instead.
  static SerializeResult SerializeList(
      const repeated_string &in,
      size_t max_elem_length, size_t max_total_length,
      std::string *result);
  SerializeResult WriteList(const repeated_string &in, size_t max_elem_length,
                            size_t max_total_length);

  SerializeResult WriteDigitallySigned(const ct::DigitallySigned &sig);

  static SerializeResult CheckKeyHashFormat(const std::string &key_hash);

  static SerializeResult CheckSignatureFormat(const ct::DigitallySigned &sig);

  static SerializeResult CheckCertificateFormat(const std::string &cert);

  static SerializeResult CheckExtensionsFormat(const std::string &extensions);

  static SerializeResult CheckChainFormat(const repeated_string &chain);

  static SerializeResult
  CheckX509ChainEntryFormat(const ct::X509ChainEntry &entry);

  static SerializeResult
  CheckPrecertChainEntryFormat(const ct::PrecertChainEntry &entry);

  std::string output_;
};

class Deserializer {
 public:
  // We do not make a copy, so input must remain valid.
  explicit Deserializer(const std::string &input);
  ~Deserializer() {}

  enum DeserializeResult {
    OK,
    INPUT_TOO_SHORT,
    INVALID_HASH_ALGORITHM,
    INVALID_SIGNATURE_ALGORITHM,
    INPUT_TOO_LONG,
    UNSUPPORTED_VERSION,
    INVALID_LIST_ENCODING,
    EMPTY_LIST,
    EMPTY_ELEM_IN_LIST,
  };

  bool ReachedEnd() const { return bytes_remaining_ == 0; }

  DeserializeResult ReadSCT(ct::SignedCertificateTimestamp *sct);

  static DeserializeResult DeserializeSCT(const std::string &in,
                                          ct::SignedCertificateTimestamp *sct);

  static DeserializeResult DeserializeSCTList(
      const std::string &in, ct::SignedCertificateTimestampList *sct_list);

  static DeserializeResult
  DeserializeDigitallySigned(const std::string &in, ct::DigitallySigned *sig);

  // Deserialize the certificate_chain component of an X509ChainEntry and plug
  // it to the entry.
  static DeserializeResult DeserializeX509Chain(
      const std::string &in, ct::X509ChainEntry *x509_chain_entry);

  static DeserializeResult DeserializePrecertChainEntry(
      const std::string &in, ct::PrecertChainEntry *precert_chain_entry);

  template<class T>
  static DeserializeResult DeserializeUint(const std::string &in, size_t bytes,
                                           T *result) {
    Deserializer deserializer(in);
    bool res = deserializer.ReadUint(bytes, result);
    if (!res)
      return INPUT_TOO_SHORT;
    if (!deserializer.ReachedEnd())
      return INPUT_TOO_LONG;
    return OK;
  }

 private:
  template<class T>
  bool ReadUint(size_t bytes, T *result) {
    if (bytes_remaining_ < bytes)
      return false;
    T res = 0;
    for (size_t i = 0; i < bytes; ++i) {
      res = (res << 8) | static_cast<unsigned char>(*current_pos_);
      ++current_pos_;
    }

    bytes_remaining_ -= bytes;
    *result = res;
    return true;
  }

  bool ReadFixedBytes(size_t bytes, std::string *result);

  bool ReadLengthPrefix(size_t max_length, size_t *result);

  bool ReadVarBytes(size_t max_length, std::string *result);

  // FIXME(ekasper): for simplicity these reject if the list has empty
  // empty elements (all our use cases are like this) but they should take in
  // an arbitrary min bound instead.
  static DeserializeResult DeserializeList(const std::string &in,
                                           size_t max_total_length,
                                           size_t max_elem_length,
                                           repeated_string *out);
  DeserializeResult ReadList(size_t max_total_length, size_t max_elem_length,
                             repeated_string *out);

  DeserializeResult ReadDigitallySigned(ct::DigitallySigned *sig);

  const char *current_pos_;
  size_t bytes_remaining_;
};
#endif
