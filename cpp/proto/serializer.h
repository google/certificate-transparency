#ifndef CERT_TRANS_PROTO_SERIALIZER_H_
#define CERT_TRANS_PROTO_SERIALIZER_H_

#include <glog/logging.h>
#include <google/protobuf/repeated_field.h>
#include <stdint.h>
#include <functional>
#include <string>

#include "base/macros.h"
#include "proto/ct.pb.h"
#include "proto/tls_encoding.h"

typedef google::protobuf::RepeatedPtrField<ct::SthExtension>
    repeated_sth_extension;
typedef google::protobuf::RepeatedPtrField<ct::SctExtension>
    repeated_sct_extension;

cert_trans::serialization::SerializeResult CheckExtensionsFormat(
    const std::string& extensions);
cert_trans::serialization::SerializeResult CheckKeyHashFormat(
    const std::string& key_hash);
cert_trans::serialization::SerializeResult CheckSctExtensionsFormat(
    const repeated_sct_extension& extension);

void WriteSctExtension(const repeated_sct_extension& extension,
                       std::string* output);

cert_trans::serialization::DeserializeResult ReadExtensionsV1(
    TLSDeserializer* deserializer, ct::TimestampedEntry* entry);

cert_trans::serialization::DeserializeResult ReadSCT(
    TLSDeserializer* deserializer, ct::SignedCertificateTimestamp* sct);

cert_trans::serialization::DeserializeResult ReadMerkleTreeLeaf(
    TLSDeserializer* deserializer, ct::MerkleTreeLeaf* leaf);

// A utility class for writing protocol buffer fields in canonical TLS style.
class Serializer {
 public:
  static const size_t kMaxV2ExtensionType;
  static const size_t kMaxV2ExtensionsCount;
  static const size_t kMaxExtensionsLength;
  static const size_t kMaxSerializedSCTLength;
  static const size_t kMaxSCTListLength;

  static const size_t kLogEntryTypeLengthInBytes;
  static const size_t kSignatureTypeLengthInBytes;
  static const size_t kVersionLengthInBytes;
  // Log Key ID
  static const size_t kKeyIDLengthInBytes;
  static const size_t kMerkleLeafTypeLengthInBytes;
  // Public key hash from cert
  static const size_t kKeyHashLengthInBytes;
  static const size_t kTimestampLengthInBytes;

  // API
  // TODO(alcutter): typedef these function<> bits
  static void ConfigureV1(
      const std::function<std::string(const ct::LogEntry&)>& leaf_data,
      const std::function<cert_trans::serialization::SerializeResult(
          const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
          std::string* result)>& serialize_sct_sig_input,
      const std::function<cert_trans::serialization::SerializeResult(
          const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
          std::string* result)>& serialize_sct_merkle_leaf);

  static void ConfigureV2(
      const std::function<std::string(const ct::LogEntry&)>& leaf_data,
      const std::function<cert_trans::serialization::SerializeResult(
          const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
          std::string* result)>& serialize_sct_sig_input,
      const std::function<cert_trans::serialization::SerializeResult(
          const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
          std::string* result)>& serialize_sct_merkle_leaf);

  static std::string LeafData(const ct::LogEntry& entry);

  static cert_trans::serialization::SerializeResult SerializeSTHSignatureInput(
      const ct::SignedTreeHead& sth, std::string* result);

  static cert_trans::serialization::SerializeResult SerializeSCTMerkleTreeLeaf(
      const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
      std::string* result);

  static cert_trans::serialization::SerializeResult SerializeSCTSignatureInput(
      const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
      std::string* result);

  static cert_trans::serialization::SerializeResult
  SerializeV1STHSignatureInput(uint64_t timestamp, int64_t tree_size,
                               const std::string& root_hash,
                               std::string* result);

  static cert_trans::serialization::SerializeResult
  SerializeV2STHSignatureInput(uint64_t timestamp, int64_t tree_size,
                               const std::string& root_hash,
                               const repeated_sth_extension& sth_extension,
                               const std::string& log_id, std::string* result);


  // Random utils
  static cert_trans::serialization::SerializeResult SerializeList(
      const repeated_string& in, size_t max_elem_length,
      size_t max_total_length, std::string* result);

  static cert_trans::serialization::SerializeResult SerializeSCT(
      const ct::SignedCertificateTimestamp& sct, std::string* result);

  static cert_trans::serialization::SerializeResult SerializeSCTList(
      const ct::SignedCertificateTimestampList& sct_list, std::string* result);

  static cert_trans::serialization::SerializeResult SerializeDigitallySigned(
      const ct::DigitallySigned& sig, std::string* result);

  // TODO(ekasper): tests for these!
  template <class T>
  static std::string SerializeUint(T in, size_t bytes = sizeof(T)) {
    std::string out;
    cert_trans::serialization::WriteUint(in, bytes, &out);
    return out;
  }

 private:
  // This class is mostly a namespace for static methods.
  // TODO(pphaneuf): Make this into normal functions in a namespace.
  Serializer() = delete;
};


class Deserializer {
 public:
  static void Configure(
      const std::function<cert_trans::serialization::DeserializeResult(
          TLSDeserializer* d, ct::MerkleTreeLeaf* leaf)>&
          read_merkle_tree_leaf_body);

  static cert_trans::serialization::DeserializeResult DeserializeSCT(
      const std::string& in, ct::SignedCertificateTimestamp* sct);

  static cert_trans::serialization::DeserializeResult DeserializeSCTList(
      const std::string& in, ct::SignedCertificateTimestampList* sct_list);

  static cert_trans::serialization::DeserializeResult
  DeserializeDigitallySigned(const std::string& in, ct::DigitallySigned* sig);

  // FIXME(ekasper): for simplicity these reject if the list has empty
  // elements (all our use cases are like this) but they should take in
  // an arbitrary min bound instead.
  static cert_trans::serialization::DeserializeResult DeserializeList(
      const std::string& in, size_t max_total_length, size_t max_elem_length,
      repeated_string* out);

  static cert_trans::serialization::DeserializeResult
  DeserializeMerkleTreeLeaf(const std::string& in, ct::MerkleTreeLeaf* leaf);

  // TODO(pphaneuf): Maybe the users of this should just use
  // TLSDeserializer directly?
  template <class T>
  static cert_trans::serialization::DeserializeResult DeserializeUint(
      const std::string& in, size_t bytes, T* result) {
    TLSDeserializer deserializer(in);
    bool res = deserializer.ReadUint(bytes, result);
    if (!res)
      return cert_trans::serialization::DeserializeResult::INPUT_TOO_SHORT;
    if (!deserializer.ReachedEnd())
      return cert_trans::serialization::DeserializeResult::INPUT_TOO_LONG;
    return cert_trans::serialization::DeserializeResult::OK;
  }

 private:
  // This class is mostly a namespace for static methods.
  // TODO(pphaneuf): Make this into normal functions in a namespace.
  Deserializer() = delete;

  // This should never do anything, but just in case...
  DISALLOW_COPY_AND_ASSIGN(Deserializer);
};

#endif  // CERT_TRANS_PROTO_SERIALIZER_H_
