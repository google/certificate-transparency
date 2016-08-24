/* -*- indent-tabs-mode: nil -*- */
#include "proto/xjson_serializer.h"

#include <glog/logging.h>
#include <math.h>
#include <string>

#include "proto/ct.pb.h"
#include "proto/serializer.h"

using cert_trans::serialization::SerializeResult;
using cert_trans::serialization::DeserializeResult;
using cert_trans::serialization::WriteDigitallySigned;
using cert_trans::serialization::WriteFixedBytes;
using cert_trans::serialization::WriteUint;
using cert_trans::serialization::WriteVarBytes;
using ct::DigitallySigned;
using ct::DigitallySigned_HashAlgorithm_IsValid;
using ct::DigitallySigned_SignatureAlgorithm_IsValid;
using ct::LogEntry;
using ct::LogEntryType_IsValid;
using ct::MerkleTreeLeaf;
using ct::SignedCertificateTimestamp;
using ct::SignedCertificateTimestampList;
using ct::SthExtension;
using ct::SctExtension;
using ct::Version_IsValid;
using google::protobuf::RepeatedPtrField;
using std::string;


namespace {


const size_t kMaxJsonLength = (1 << 24) - 1;


SerializeResult CheckJsonFormat(const string& json) {
  if (json.empty())
    return SerializeResult::EMPTY_CERTIFICATE;
  if (json.size() > kMaxJsonLength)
    return SerializeResult::CERTIFICATE_TOO_LONG;
  return SerializeResult::OK;
}


string V1LeafData(const LogEntry& entry) {
  CHECK(entry.has_x_json_entry());
  return entry.x_json_entry().json();
}


SerializeResult SerializeV1SCTSignatureInput(
    const SignedCertificateTimestamp& sct, const LogEntry& entry,
    string* result) {
  CHECK_NOTNULL(result);
  if (sct.version() != ct::V1) {
    return SerializeResult::UNSUPPORTED_VERSION;
  }
  const string json(entry.x_json_entry().json());
  SerializeResult res = CheckJsonFormat(json);
  if (res != SerializeResult::OK) {
    return res;
  }
  const string extensions(sct.extensions());
  res = CheckExtensionsFormat(extensions);
  if (res != SerializeResult::OK) {
    return res;
  }
  result->clear();
  WriteUint(ct::V1, Serializer::kVersionLengthInBytes, result);
  WriteUint(ct::CERTIFICATE_TIMESTAMP, Serializer::kSignatureTypeLengthInBytes,
            result);
  WriteUint(sct.timestamp(), Serializer::kTimestampLengthInBytes, result);
  WriteUint(ct::X_JSON_ENTRY, Serializer::kLogEntryTypeLengthInBytes, result);
  WriteVarBytes(json, kMaxJsonLength, result);
  WriteVarBytes(extensions, Serializer::kMaxExtensionsLength, result);
  return SerializeResult::OK;
}


SerializeResult SerializeV1SCTMerkleTreeLeaf(
    const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
    string* result) {
  CHECK_NOTNULL(result);
  if (sct.version() != ct::V1) {
    return SerializeResult::UNSUPPORTED_VERSION;
  }
  const string json(entry.x_json_entry().json());
  SerializeResult res = CheckJsonFormat(json);
  if (res != SerializeResult::OK) {
    return res;
  }
  const string extensions(sct.extensions());
  res = CheckExtensionsFormat(extensions);
  if (res != SerializeResult::OK) {
    return res;
  }
  result->clear();
  WriteUint(ct::V1, Serializer::kVersionLengthInBytes, result);
  WriteUint(ct::TIMESTAMPED_ENTRY, Serializer::kMerkleLeafTypeLengthInBytes,
            result);
  WriteUint(sct.timestamp(), Serializer::kTimestampLengthInBytes, result);
  WriteUint(ct::X_JSON_ENTRY, Serializer::kLogEntryTypeLengthInBytes, result);
  WriteVarBytes(json, kMaxJsonLength, result);
  WriteVarBytes(extensions, Serializer::kMaxExtensionsLength, result);
  return SerializeResult::OK;
}


DeserializeResult DeserializeV1SCTMerkleTreeLeaf(TLSDeserializer* des,
                                                 MerkleTreeLeaf* leaf) {
  CHECK_NOTNULL(des);
  CHECK_NOTNULL(leaf);

  unsigned int version;
  if (!des->ReadUint(Serializer::kVersionLengthInBytes, &version)) {
    return DeserializeResult::INPUT_TOO_SHORT;
  }

  if (version != ct::V1) {
    return DeserializeResult::UNSUPPORTED_VERSION;
  }
  leaf->set_version(ct::V1);

  unsigned int type;
  if (!des->ReadUint(Serializer::kMerkleLeafTypeLengthInBytes, &type)) {
    return DeserializeResult::INPUT_TOO_SHORT;
  }
  if (type != ct::TIMESTAMPED_ENTRY) {
    return DeserializeResult::UNKNOWN_LEAF_TYPE;
  }
  leaf->set_type(ct::TIMESTAMPED_ENTRY);

  ct::TimestampedEntry* const entry = leaf->mutable_timestamped_entry();

  uint64_t timestamp;
  if (!des->ReadUint(Serializer::kTimestampLengthInBytes, &timestamp)) {
    return DeserializeResult::INPUT_TOO_SHORT;
  }
  entry->set_timestamp(timestamp);

  unsigned int entry_type;
  if (!des->ReadUint(Serializer::kLogEntryTypeLengthInBytes, &entry_type)) {
    return DeserializeResult::INPUT_TOO_SHORT;
  }

  CHECK(LogEntryType_IsValid(entry_type));
  entry->set_entry_type(static_cast<ct::LogEntryType>(entry_type));

  switch (entry_type) {
    case ct::X_JSON_ENTRY: {
      string json;
      if (!des->ReadVarBytes(kMaxJsonLength, &json)) {
        return DeserializeResult::INPUT_TOO_SHORT;
      }
      entry->mutable_signed_entry()->set_json(json);
      return ReadExtensionsV1(des, entry);
    }

    case ct::UNKNOWN_ENTRY_TYPE: {
      // handled below.
      break;
    }
  }
  return DeserializeResult::UNKNOWN_LOGENTRY_TYPE;
}


}  // namespace


void ConfigureSerializerForV1XJSON() {
  Serializer::ConfigureV1(V1LeafData, SerializeV1SCTSignatureInput,
                          SerializeV1SCTMerkleTreeLeaf);
  Deserializer::Configure(DeserializeV1SCTMerkleTreeLeaf);
}
