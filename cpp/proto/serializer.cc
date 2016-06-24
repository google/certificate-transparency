/* -*- indent-tabs-mode: nil -*- */
#include "proto/serializer.h"

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <math.h>
#include <string>

#include "proto/ct.pb.h"

using cert_trans::serialization::internal::PrefixLength;
using cert_trans::serialization::SerializeResult;
using cert_trans::serialization::DeserializeResult;
using cert_trans::serialization::WriteDigitallySigned;
using cert_trans::serialization::WriteFixedBytes;
using cert_trans::serialization::WriteUint;
using cert_trans::serialization::WriteVarBytes;
using cert_trans::serialization::constants::kMaxSignatureLength;
using cert_trans::serialization::constants::kHashAlgorithmLengthInBytes;
using cert_trans::serialization::constants::kSigAlgorithmLengthInBytes;
using ct::DigitallySigned;
using ct::DigitallySigned_HashAlgorithm_IsValid;
using ct::DigitallySigned_SignatureAlgorithm_IsValid;
using ct::LogEntry;
using ct::MerkleTreeLeaf;
using ct::PrecertChainEntry;
using ct::SignedCertificateTimestamp;
using ct::SignedCertificateTimestampList;
using ct::SthExtension;
using ct::SctExtension;
using ct::Version_IsValid;
using ct::X509ChainEntry;
using google::protobuf::RepeatedPtrField;
using std::function;
using std::string;

const size_t Serializer::kMaxV2ExtensionType = (1 << 16) - 1;
const size_t Serializer::kMaxV2ExtensionsCount = (1 << 16) - 2;
const size_t Serializer::kMaxExtensionsLength = (1 << 16) - 1;
const size_t Serializer::kMaxSerializedSCTLength = (1 << 16) - 1;
const size_t Serializer::kMaxSCTListLength = (1 << 16) - 1;

const size_t Serializer::kLogEntryTypeLengthInBytes = 2;
const size_t Serializer::kSignatureTypeLengthInBytes = 1;
const size_t Serializer::kVersionLengthInBytes = 1;
const size_t Serializer::kKeyIDLengthInBytes = 32;
const size_t Serializer::kMerkleLeafTypeLengthInBytes = 1;
const size_t Serializer::kKeyHashLengthInBytes = 32;
const size_t Serializer::kTimestampLengthInBytes = 8;

DEFINE_bool(allow_reconfigure_serializer_test_only, false,
            "Allow tests to reconfigure the serializer multiple times.");

// TODO(pphaneuf): This is just to avoid causing diff churn while
// refactoring. Functions for internal use only should be put together
// in an anonymous namespace.
SerializeResult CheckSthExtensionsFormat(
    const repeated_sth_extension& extension);


namespace {


function<string(const ct::LogEntry&)> leaf_data;

function<SerializeResult(const ct::SignedCertificateTimestamp& sct,
                         const ct::LogEntry& entry, std::string* result)>
    serialize_sct_sig_input;

function<SerializeResult(const ct::SignedCertificateTimestamp& sct,
                         const ct::LogEntry& entry, std::string* result)>
    serialize_sct_merkle_leaf;

function<SerializeResult(uint64_t timestamp, int64_t tree_size,
                         const std::string& root_hash, std::string* result)>
    serialize_sth_sig_input_v1;

function<SerializeResult(uint64_t timestamp, int64_t tree_size,
                         const std::string& root_hash,
                         const repeated_sth_extension& sth_extension,
                         const std::string& log_id, std::string* result)>
    serialize_sth_sig_input_v2;

function<DeserializeResult(TLSDeserializer* d, ct::MerkleTreeLeaf* leaf)>
    read_merkle_tree_leaf;


}  // namespace


// static
string Serializer::LeafData(const LogEntry& entry) {
  CHECK(leaf_data);
  return leaf_data(entry);
}


// static
SerializeResult Serializer::SerializeV1STHSignatureInput(
    uint64_t timestamp, int64_t tree_size, const string& root_hash,
    string* result) {
  CHECK(result);
  // result will be cleared by SerializeV1STHSignatureInput
  CHECK(serialize_sth_sig_input_v1);
  return serialize_sth_sig_input_v1(timestamp, tree_size, root_hash, result);
}


static SerializeResult SerializeV1STHSignatureInput(uint64_t timestamp,
                                                    int64_t tree_size,
                                                    const string& root_hash,
                                                    string* result) {
  CHECK_GE(tree_size, 0);
  result->clear();
  if (root_hash.size() != 32)
    return SerializeResult::INVALID_HASH_LENGTH;
  WriteUint(ct::V1, Serializer::kVersionLengthInBytes, result);
  WriteUint(ct::TREE_HEAD, Serializer::kSignatureTypeLengthInBytes, result);
  WriteUint(timestamp, Serializer::kTimestampLengthInBytes, result);
  WriteUint(tree_size, 8, result);
  WriteFixedBytes(root_hash, result);
  return SerializeResult::OK;
}


// static
SerializeResult Serializer::SerializeV2STHSignatureInput(
    uint64_t timestamp, int64_t tree_size, const string& root_hash,
    const repeated_sth_extension& sth_extension, const string& log_id,
    string* result) {
  CHECK(result);
  CHECK(serialize_sth_sig_input_v2);
  return serialize_sth_sig_input_v2(timestamp, tree_size, root_hash,
                                     sth_extension, log_id, result);
}


static SerializeResult SerializeV2STHSignatureInput(
    uint64_t timestamp, int64_t tree_size, const string& root_hash,
    const RepeatedPtrField<SthExtension>& sth_extension, const string& log_id,
    string* result) {
  CHECK_GE(tree_size, 0);
  result->clear();
  if (root_hash.size() != 32) {
    return SerializeResult::INVALID_HASH_LENGTH;
  }
  SerializeResult res = CheckSthExtensionsFormat(sth_extension);
  if (res != SerializeResult::OK) {
    return res;
  }
  if (log_id.size() != Serializer::kKeyIDLengthInBytes) {
    return SerializeResult::INVALID_KEYID_LENGTH;
  }

  WriteUint(ct::V2, Serializer::kVersionLengthInBytes, result);
  WriteUint(ct::TREE_HEAD, Serializer::kSignatureTypeLengthInBytes, result);
  // TODO(eranm): This is wrong, V2 Log IDs are OIDs.
  WriteFixedBytes(log_id, result);
  WriteUint(timestamp, Serializer::kTimestampLengthInBytes, result);
  WriteUint(tree_size, 8, result);
  WriteFixedBytes(root_hash, result);
  // V2 STH can have multiple extensions
  WriteUint(sth_extension.size(), 2, result);
  for (auto it = sth_extension.begin(); it != sth_extension.end(); ++it) {
    WriteUint(it->sth_extension_type(), 2, result);
    WriteVarBytes(it->sth_extension_data(), Serializer::kMaxExtensionsLength,
                  result);
  }

  return SerializeResult::OK;
}


// static
SerializeResult Serializer::SerializeSTHSignatureInput(
    const ct::SignedTreeHead& sth, std::string* result) {
  CHECK(result);
  // result will be cleared by
  // SerializeV1STHSignatureInput or SerializeV2STHSignatureInput
  // TODO(alcutter): this should know whether it's V1 or V2 from the
  // Configure()
  switch (sth.version()) {
    case ct::V1:
      return SerializeV1STHSignatureInput(sth.timestamp(), sth.tree_size(),
                                          sth.sha256_root_hash(), result);
    case ct::V2:
      return SerializeV2STHSignatureInput(sth.timestamp(), sth.tree_size(),
                                          sth.sha256_root_hash(),
                                          sth.sth_extension(),
                                          sth.id().key_id(), result);
    default:
      break;
  }
  return SerializeResult::UNSUPPORTED_VERSION;
}


// static
SerializeResult Serializer::SerializeSCTMerkleTreeLeaf(
    const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
    std::string* result) {
  CHECK(result);
  CHECK(serialize_sct_merkle_leaf);
  return serialize_sct_merkle_leaf(sct, entry, result);
}


// static
SerializeResult Serializer::SerializeSCTSignatureInput(
    const SignedCertificateTimestamp& sct, const LogEntry& entry,
    string* result) {
  CHECK(result);
  CHECK(serialize_sct_sig_input);
  return serialize_sct_sig_input(sct, entry, result);
}

SerializeResult WriteSCTV1(const SignedCertificateTimestamp& sct,
                           std::string* output) {
  CHECK(sct.version() == ct::V1);
  // output is cleared by SerializeSCT
  SerializeResult res = CheckExtensionsFormat(sct.extensions());
  if (res != SerializeResult::OK) {
    return res;
  }
  if (sct.id().key_id().size() != Serializer::kKeyIDLengthInBytes) {
    return SerializeResult::INVALID_KEYID_LENGTH;
  }
  WriteUint(sct.version(), Serializer::kVersionLengthInBytes, output);
  WriteFixedBytes(sct.id().key_id(), output);
  WriteUint(sct.timestamp(), Serializer::kTimestampLengthInBytes, output);
  WriteVarBytes(sct.extensions(), Serializer::kMaxExtensionsLength, output);
  return WriteDigitallySigned(sct.signature(), output);
}

void WriteSctExtension(const RepeatedPtrField<SctExtension>& extension,
                       std::string* output) {
  WriteUint(extension.size(), 2, output);
  for (auto it = extension.begin(); it != extension.end(); ++it) {
    WriteUint(it->sct_extension_type(), 2, output);
    WriteVarBytes(it->sct_extension_data(), Serializer::kMaxExtensionsLength,
                  output);
  }
}

SerializeResult WriteSCTV2(const SignedCertificateTimestamp& sct,
                           std::string* output) {
  CHECK(sct.version() == ct::V2);
  // output is cleared by SerializeSCT
  SerializeResult res = CheckSctExtensionsFormat(sct.sct_extension());
  if (res != SerializeResult::OK) {
    return res;
  }
  if (sct.id().key_id().size() != Serializer::kKeyIDLengthInBytes) {
    return SerializeResult::INVALID_KEYID_LENGTH;
  }
  WriteUint(sct.version(), Serializer::kVersionLengthInBytes, output);
  WriteFixedBytes(sct.id().key_id(), output);
  WriteUint(sct.timestamp(), Serializer::kTimestampLengthInBytes, output);
  // V2 SCT can have a number of extensions. They must be ordered by type
  // but we already checked that above.
  WriteSctExtension(sct.sct_extension(), output);
  return WriteDigitallySigned(sct.signature(), output);
}

// static
SerializeResult Serializer::SerializeSCT(const SignedCertificateTimestamp& sct,
                                         string* result) {
  SerializeResult res = SerializeResult::UNSUPPORTED_VERSION;

  result->clear();
  switch (sct.version()) {
    case ct::V1:
      res = WriteSCTV1(sct, result);
      break;
    case ct::V2:
      res = WriteSCTV2(sct, result);
      break;
    default:
      res = SerializeResult::UNSUPPORTED_VERSION;
  }
  if (res != SerializeResult::OK) {
    result->clear();
    return res;
  }
  return SerializeResult::OK;
}

// static
SerializeResult Serializer::SerializeSCTList(
    const SignedCertificateTimestampList& sct_list, string* result) {
  if (sct_list.sct_list_size() == 0) {
    return SerializeResult::EMPTY_LIST;
  }
  return SerializeList(sct_list.sct_list(),
                       Serializer::kMaxSerializedSCTLength,
                       Serializer::kMaxSCTListLength, result);
}

// static
SerializeResult Serializer::SerializeDigitallySigned(
    const DigitallySigned& sig, string* result) {
  result->clear();
  return WriteDigitallySigned(sig, result);
}

// static
SerializeResult Serializer::SerializeList(const repeated_string& in,
                                          size_t max_elem_length,
                                          size_t max_total_length,
                                          string* result) {
  std::string output;
  SerializeResult res =
      cert_trans::serialization::WriteList(in, max_elem_length,
                                           max_total_length, &output);
  if (res != SerializeResult::OK)
    return res;
  result->assign(output);
  return SerializeResult::OK;
}

SerializeResult CheckKeyHashFormat(const string& key_hash) {
  if (key_hash.size() != Serializer::kKeyHashLengthInBytes)
    return SerializeResult::INVALID_HASH_LENGTH;
  return SerializeResult::OK;
}


SerializeResult CheckExtensionsFormat(const string& extensions) {
  if (extensions.size() > Serializer::kMaxExtensionsLength)
    return SerializeResult::EXTENSIONS_TOO_LONG;
  return SerializeResult::OK;
}


// Checks the (v2) STH extensions are correct. The RFC defines that there can
// be up to 65534 of them and each one can contain up to 65535 bytes.
// They must be in ascending order of extension type.
SerializeResult CheckSthExtensionsFormat(
    const repeated_sth_extension& extension) {
  if (extension.size() > static_cast<int>(Serializer::kMaxV2ExtensionsCount)) {
    return SerializeResult::EXTENSIONS_TOO_LONG;
  }

  uint32_t last_type_seen = 0;

  for (auto it = extension.begin(); it != extension.end(); ++it) {
    if (it->sth_extension_type() > Serializer::kMaxV2ExtensionType) {
      return SerializeResult::INVALID_ENTRY_TYPE;
    }

    if (it->sth_extension_data().size() > Serializer::kMaxExtensionsLength) {
      return SerializeResult::EXTENSIONS_TOO_LONG;
    }

    if (it->sth_extension_type() < last_type_seen) {
      // It's out of order - reject
      return SerializeResult::EXTENSIONS_NOT_ORDERED;
    }

    last_type_seen = it->sth_extension_type();
  }

  return SerializeResult::OK;
}


// Checks the (v2) SCT extensions are correct. The RFC defines that there can
// be up to 65534 of them and each one can contain up to 65535 bytes. They
// must be in ascending order of extension type
SerializeResult CheckSctExtensionsFormat(
    const RepeatedPtrField<SctExtension>& extension) {
  if (extension.size() > static_cast<int>(Serializer::kMaxV2ExtensionsCount)) {
    return SerializeResult::EXTENSIONS_TOO_LONG;
  }

  uint32_t last_type_seen = 0;

  for (auto it = extension.begin(); it != extension.end(); ++it) {
    if (it->sct_extension_data().size() > Serializer::kMaxExtensionsLength) {
      return SerializeResult::EXTENSIONS_TOO_LONG;
    }

    if (it->sct_extension_type() > Serializer::kMaxV2ExtensionType) {
      return SerializeResult::INVALID_ENTRY_TYPE;
    }

    if (it->sct_extension_type() < last_type_seen) {
      // It's out of order - reject
      return SerializeResult::EXTENSIONS_NOT_ORDERED;
    }

    last_type_seen = it->sct_extension_type();
  }

  return SerializeResult::OK;
}


namespace {

DeserializeResult ReadSCTV1(TLSDeserializer* deserializer,
                            SignedCertificateTimestamp* sct) {
  sct->set_version(ct::V1);
  if (!deserializer->ReadFixedBytes(Serializer::kKeyIDLengthInBytes,
                                    sct->mutable_id()->mutable_key_id())) {
    return DeserializeResult::INPUT_TOO_SHORT;
  }
  // V1 encoding.
  uint64_t timestamp = 0;
  if (!deserializer->ReadUint(Serializer::kTimestampLengthInBytes,
                              &timestamp)) {
    return DeserializeResult::INPUT_TOO_SHORT;
  }
  sct->set_timestamp(timestamp);
  string extensions;
  if (!deserializer->ReadVarBytes(Serializer::kMaxExtensionsLength,
                                  &extensions)) {
    // In theory, could also be an invalid length prefix, but not if
    // length limits follow byte boundaries.
    return DeserializeResult::INPUT_TOO_SHORT;
  }
  return deserializer->ReadDigitallySigned(sct->mutable_signature());
}

const size_t kV2ExtensionCountLengthInBytes = 2;
const size_t kV2ExtensionTypeLengthInBytes = 2;

DeserializeResult ReadSctExtension(TLSDeserializer* deserializer,
                                   RepeatedPtrField<SctExtension>* extension) {
  uint32_t ext_count;
  if (!deserializer->ReadUint(kV2ExtensionCountLengthInBytes, &ext_count)) {
    return DeserializeResult::INPUT_TOO_SHORT;
  }

  if (ext_count > Serializer::kMaxV2ExtensionsCount) {
    return DeserializeResult::EXTENSIONS_TOO_LONG;
  }

  for (uint32_t ext = 0; ext < ext_count; ++ext) {
    uint32_t ext_type;
    if (!deserializer->ReadUint(kV2ExtensionTypeLengthInBytes, &ext_type)) {
      return DeserializeResult::INPUT_TOO_SHORT;
    }

    string ext_data;
    if (!deserializer->ReadVarBytes(Serializer::kMaxExtensionsLength,
                                    &ext_data)) {
      return DeserializeResult::INPUT_TOO_SHORT;
    }

    SctExtension* new_ext = extension->Add();
    new_ext->set_sct_extension_type(ext_type);
    new_ext->set_sct_extension_data(ext_data);
  }

  // This makes sure they're correctly ordered (See RFC section 5.3)
  return CheckSctExtensionsFormat(*extension) == SerializeResult::OK
             ? DeserializeResult::OK
             : DeserializeResult::EXTENSIONS_NOT_ORDERED;
}

DeserializeResult ReadSCTV2(TLSDeserializer* deserializer,
                            SignedCertificateTimestamp* sct) {
  sct->set_version(ct::V2);
  if (!deserializer->ReadFixedBytes(Serializer::kKeyIDLengthInBytes,
                                    sct->mutable_id()->mutable_key_id())) {
    return DeserializeResult::INPUT_TOO_SHORT;
  }
  // V2 encoding.
  uint64_t timestamp = 0;
  if (!deserializer->ReadUint(Serializer::kTimestampLengthInBytes,
                              &timestamp)) {
    return DeserializeResult::INPUT_TOO_SHORT;
  }
  sct->set_timestamp(timestamp);
  // Extensions are handled differently for V2
  const DeserializeResult res =
      ReadSctExtension(deserializer, sct->mutable_sct_extension());
  if (res != DeserializeResult::OK) {
    return res;
  }
  return deserializer->ReadDigitallySigned(sct->mutable_signature());
}

}  // namespace


DeserializeResult ReadExtensionsV1(TLSDeserializer* deserializer,
                                   ct::TimestampedEntry* entry) {
  CHECK_NOTNULL(deserializer);
  string extensions;
  if (!deserializer->ReadVarBytes(Serializer::kMaxExtensionsLength,
                                  &extensions)) {
    return DeserializeResult::INPUT_TOO_SHORT;
  }
  CHECK_NOTNULL(entry)->set_extensions(extensions);
  return DeserializeResult::OK;
}


DeserializeResult ReadSCT(TLSDeserializer* deserializer,
                          SignedCertificateTimestamp* sct) {
  int version;
  if (!deserializer->ReadUint(Serializer::kVersionLengthInBytes, &version)) {
    return DeserializeResult::INPUT_TOO_SHORT;
  }
  if (!Version_IsValid(version) || (version != ct::V1 && version != ct::V2)) {
    return DeserializeResult::UNSUPPORTED_VERSION;
  }

  switch (version) {
    case ct::V1:
      return ReadSCTV1(deserializer, sct);
      break;

    case ct::V2:

      return ReadSCTV2(deserializer, sct);
      break;

    default:
      return DeserializeResult::UNSUPPORTED_VERSION;
  }
}


// static
DeserializeResult Deserializer::DeserializeSCT(
    const string& in, SignedCertificateTimestamp* sct) {
  TLSDeserializer deserializer(in);
  DeserializeResult res = ReadSCT(&deserializer, sct);
  if (res != DeserializeResult::OK) {
    return res;
  }
  if (!deserializer.ReachedEnd()) {
    return DeserializeResult::INPUT_TOO_LONG;
  }
  return DeserializeResult::OK;
}


// static
DeserializeResult Deserializer::DeserializeSCTList(
    const string& in, SignedCertificateTimestampList* sct_list) {
  sct_list->clear_sct_list();
  DeserializeResult res = DeserializeList(in, Serializer::kMaxSCTListLength,
                                          Serializer::kMaxSerializedSCTLength,
                                          sct_list->mutable_sct_list());
  if (res != DeserializeResult::OK)
    return res;
  if (sct_list->sct_list_size() == 0)
    return DeserializeResult::EMPTY_LIST;
  return DeserializeResult::OK;
}


// static
DeserializeResult Deserializer::DeserializeDigitallySigned(
    const string& in, DigitallySigned* sig) {
  TLSDeserializer deserializer(in);
  DeserializeResult res = deserializer.ReadDigitallySigned(sig);
  if (res != DeserializeResult::OK)
    return res;
  if (!deserializer.ReachedEnd())
    return DeserializeResult::INPUT_TOO_LONG;
  return DeserializeResult::OK;
}



// static
DeserializeResult Deserializer::DeserializeList(const string& in,
                                                size_t max_total_length,
                                                size_t max_elem_length,
                                                repeated_string* out) {
  TLSDeserializer deserializer(in);
  DeserializeResult res =
      deserializer.ReadList(max_total_length, max_elem_length, out);
  if (res != DeserializeResult::OK)
    return res;
  if (!deserializer.ReachedEnd())
    return DeserializeResult::INPUT_TOO_LONG;
  return DeserializeResult::OK;
}



DeserializeResult Deserializer::DeserializeMerkleTreeLeaf(
    const std::string& in, ct::MerkleTreeLeaf* leaf) {
  TLSDeserializer des(in);

  DeserializeResult ret = read_merkle_tree_leaf(&des, leaf);
  if (ret != DeserializeResult::OK) {
    return ret;
  }

  if (!des.ReachedEnd()) {
    return DeserializeResult::INPUT_TOO_LONG;
  }

  return DeserializeResult::OK;
}


// static
void Serializer::ConfigureV1(
    const function<string(const ct::LogEntry&)>& leaf_data_func,
    const function<SerializeResult(
        const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
        std::string* result)>& serialize_sct_sig_input_func,
    const function<SerializeResult(
        const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
        std::string* result)>& serialize_sct_merkle_leaf_func) {
  CHECK(FLAGS_allow_reconfigure_serializer_test_only ||
        (!leaf_data&& !serialize_sct_sig_input &&
         !serialize_sct_merkle_leaf))
      << "Serializer already configured";
  leaf_data = leaf_data_func;
  serialize_sct_sig_input = serialize_sct_sig_input_func;
  serialize_sct_merkle_leaf = serialize_sct_merkle_leaf_func;
  serialize_sth_sig_input_v1 = ::SerializeV1STHSignatureInput;
}


// static
void Serializer::ConfigureV2(
    const function<string(const ct::LogEntry&)>& leaf_data_func,
    const function<SerializeResult(
        const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
        std::string* result)>& serialize_sct_sig_input_func,
    const function<SerializeResult(
        const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
        std::string* result)>& serialize_sct_merkle_leaf_func) {
  CHECK(FLAGS_allow_reconfigure_serializer_test_only ||
        (!leaf_data && !serialize_sct_sig_input &&
         !serialize_sct_merkle_leaf))
      << "Serializer already configured";
  leaf_data = leaf_data_func;
  serialize_sct_sig_input = serialize_sct_sig_input_func;
  serialize_sct_merkle_leaf = serialize_sct_merkle_leaf_func;
  serialize_sth_sig_input_v2 = ::SerializeV2STHSignatureInput;
}


// static
void Deserializer::Configure(
    const function<DeserializeResult(TLSDeserializer* d,
                                     ct::MerkleTreeLeaf* leaf)>&
        read_merkle_tree_leaf_func) {
  CHECK(FLAGS_allow_reconfigure_serializer_test_only ||
        !read_merkle_tree_leaf)
      << "Deserializer already configured";
  read_merkle_tree_leaf = read_merkle_tree_leaf_func;
}
