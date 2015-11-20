/* -*- indent-tabs-mode: nil -*- */
#include "proto/serializer.h"

#include <glog/logging.h>
#include <math.h>
#include <string>

#include "proto/ct.pb.h"

using ct::DigitallySigned;
using ct::DigitallySigned_HashAlgorithm_IsValid;
using ct::DigitallySigned_SignatureAlgorithm_IsValid;
using ct::LogEntry;
using ct::LogEntryType_IsValid;
using ct::PrecertChainEntry;
using ct::SignedCertificateTimestamp;
using ct::SignedCertificateTimestampList;
using ct::SthExtension;
using ct::SctExtension;
using ct::Version_IsValid;
using ct::X509ChainEntry;
using google::protobuf::RepeatedPtrField;
using std::string;

const size_t Serializer::kMaxCertificateLength = (1 << 24) - 1;
const size_t Serializer::kMaxCertificateChainLength = (1 << 24) - 1;
const size_t Serializer::kMaxSignatureLength = (1 << 16) - 1;
const size_t Serializer::kMaxV2ExtensionType = (1 << 16) - 1;
const size_t Serializer::kMaxV2ExtensionsCount = (1 << 16) - 2;
const size_t Serializer::kMaxExtensionsLength = (1 << 16) - 1;
const size_t Serializer::kMaxSerializedSCTLength = (1 << 16) - 1;
const size_t Serializer::kMaxSCTListLength = (1 << 16) - 1;

const size_t Serializer::kLogEntryTypeLengthInBytes = 2;
const size_t Serializer::kSignatureTypeLengthInBytes = 1;
const size_t Serializer::kHashAlgorithmLengthInBytes = 1;
const size_t Serializer::kSigAlgorithmLengthInBytes = 1;
const size_t Serializer::kVersionLengthInBytes = 1;
const size_t Serializer::kKeyIDLengthInBytes = 32;
const size_t Serializer::kMerkleLeafTypeLengthInBytes = 1;
const size_t Serializer::kKeyHashLengthInBytes = 32;
const size_t Serializer::kTimestampLengthInBytes = 8;

// static
// Returns the number of bytes needed to store a value up to max_length.
size_t Serializer::PrefixLength(size_t max_length) {
  CHECK_GT(max_length, 0U);
  return ceil(log2(max_length) / float(8));
}

// static
Serializer::SerializeResult Serializer::CheckLogEntryFormatV1(
    const LogEntry& entry) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      return CheckX509ChainEntryFormatV1(entry.x509_entry());
    case ct::PRECERT_ENTRY:
      return CheckPrecertChainEntryFormatV1(entry.precert_entry());
    case ct::PRECERT_ENTRY_V2:
      LOG(INFO) << "Unexpected PRECERT_V2 in V1 log entry";
      return INVALID_ENTRY_TYPE;
    default:
      return INVALID_ENTRY_TYPE;
  }
}

// static
Serializer::SerializeResult Serializer::CheckLogEntryFormatV2(
    const LogEntry& entry) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      return CheckX509ChainEntryFormatV2(entry.x509_entry());
    case ct::PRECERT_ENTRY:
      LOG(INFO) << "Unexpected PRECERT_V1 in V2 log entry";
      return INVALID_ENTRY_TYPE;
    case ct::PRECERT_ENTRY_V2:
      return CheckPrecertChainEntryFormatV2(entry.precert_entry());
    default:
      return INVALID_ENTRY_TYPE;
  }
}

// static
string Serializer::LeafData(const LogEntry& entry) {
  switch (entry.type()) {
    // TODO(mhs): Because there is no X509_ENTRY_V2 we have to assume that
    // whichever of the cert fields is set defines the entry type. In other
    // words this is V2 if it has a CertInfo. Might be possible
    // to pass the type when the code that calls this is updated for V2.
    case ct::X509_ENTRY:
      if (entry.x509_entry().has_cert_info()) {
        CHECK(entry.x509_entry().cert_info().has_tbs_certificate())
            << "Missing V2 leaf certificate";
        return entry.x509_entry().cert_info().tbs_certificate();
      } else {
        CHECK(entry.x509_entry().has_leaf_certificate())
            << "Missing leaf certificate";
        return entry.x509_entry().leaf_certificate();
      }
    case ct::PRECERT_ENTRY:
      // Must not have both v1 and v2 entries set
      CHECK(!entry.precert_entry().has_cert_info());
      CHECK(entry.precert_entry().pre_cert().has_tbs_certificate())
          << "Missing tbs certificate (V1)";
      return entry.precert_entry().pre_cert().tbs_certificate();
    case ct::PRECERT_ENTRY_V2:
      // Must not have both v1 and v2 entries set
      CHECK(!entry.precert_entry().has_pre_cert());
      CHECK(entry.precert_entry().cert_info().has_tbs_certificate())
          << "Missing tbs certificate (V2)";
      return entry.precert_entry().cert_info().tbs_certificate();
    case ct::X_JSON_ENTRY:
      CHECK(entry.x_json_entry().has_json()) << "Missing json";
      return entry.x_json_entry().json();
    default:
      LOG(FATAL) << "Invalid entry type " << entry.type();
  }
}

// static
Serializer::SerializeResult Serializer::SerializeV1CertSCTSignatureInput(
    uint64_t timestamp, const string& certificate, const string& extensions,
    string* result) {
  SerializeResult res = CheckCertificateFormat(certificate);
  if (res != OK)
    return res;
  res = CheckExtensionsFormat(extensions);
  if (res != OK)
    return res;
  Serializer serializer;
  serializer.WriteUint(ct::V1, kVersionLengthInBytes);
  serializer.WriteUint(ct::CERTIFICATE_TIMESTAMP, kSignatureTypeLengthInBytes);
  serializer.WriteUint(timestamp, kTimestampLengthInBytes);
  serializer.WriteUint(ct::X509_ENTRY, kLogEntryTypeLengthInBytes);
  serializer.WriteVarBytes(certificate, kMaxCertificateLength);
  serializer.WriteVarBytes(extensions, kMaxExtensionsLength);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeV2CertSCTSignatureInput(
    uint64_t timestamp, const string& issuer_key_hash,
    const string& tbs_certificate,
    const RepeatedPtrField<ct::SctExtension>& sct_extension, string* result) {
  SerializeResult res = CheckCertificateFormat(tbs_certificate);
  if (res != OK)
    return res;
  res = CheckSctExtensionsFormat(sct_extension);
  if (res != OK)
    return res;
  Serializer serializer;
  serializer.WriteUint(ct::V2, kVersionLengthInBytes);
  serializer.WriteUint(ct::CERTIFICATE_TIMESTAMP, kSignatureTypeLengthInBytes);
  serializer.WriteUint(timestamp, kTimestampLengthInBytes);
  serializer.WriteUint(ct::X509_ENTRY, kLogEntryTypeLengthInBytes);
  serializer.WriteFixedBytes(issuer_key_hash);
  serializer.WriteVarBytes(tbs_certificate, kMaxCertificateLength);
  serializer.WriteSctExtension(sct_extension);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeV1PrecertSCTSignatureInput(
    uint64_t timestamp, const string& issuer_key_hash,
    const string& tbs_certificate, const string& extensions, string* result) {
  SerializeResult res = CheckCertificateFormat(tbs_certificate);
  if (res != OK)
    return res;
  res = CheckKeyHashFormat(issuer_key_hash);
  if (res != OK)
    return res;
  res = CheckExtensionsFormat(extensions);
  if (res != OK)
    return res;
  Serializer serializer;
  serializer.WriteUint(ct::V1, kVersionLengthInBytes);
  serializer.WriteUint(ct::CERTIFICATE_TIMESTAMP, kSignatureTypeLengthInBytes);
  serializer.WriteUint(timestamp, kTimestampLengthInBytes);
  serializer.WriteUint(ct::PRECERT_ENTRY, kLogEntryTypeLengthInBytes);
  serializer.WriteFixedBytes(issuer_key_hash);
  serializer.WriteVarBytes(tbs_certificate, kMaxCertificateLength);
  serializer.WriteVarBytes(extensions, kMaxExtensionsLength);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeV2PrecertSCTSignatureInput(
    uint64_t timestamp, const string& issuer_key_hash,
    const string& tbs_certificate,
    const RepeatedPtrField<ct::SctExtension>& sct_extension, string* result) {
  SerializeResult res = CheckCertificateFormat(tbs_certificate);
  if (res != OK) {
    return res;
  }
  res = CheckSctExtensionsFormat(sct_extension);
  if (res != OK) {
    return res;
  }
  Serializer serializer;
  serializer.WriteUint(ct::V2, kVersionLengthInBytes);
  serializer.WriteUint(ct::CERTIFICATE_TIMESTAMP, kSignatureTypeLengthInBytes);
  serializer.WriteUint(timestamp, kTimestampLengthInBytes);
  serializer.WriteUint(ct::PRECERT_ENTRY_V2, kLogEntryTypeLengthInBytes);
  serializer.WriteFixedBytes(issuer_key_hash);
  serializer.WriteVarBytes(tbs_certificate, kMaxCertificateLength);
  serializer.WriteSctExtension(sct_extension);
  result->assign(serializer.SerializedString());
  return OK;
}

Serializer::SerializeResult Serializer::SerializeV1XJsonSCTSignatureInput(
    uint64_t timestamp, const string& json, const string& extensions,
    string* result) {
  CHECK_NOTNULL(result);
  // TODO(alcutter): CheckJsonFormat()?
  SerializeResult res = CheckCertificateFormat(json);
  if (res != OK) {
    return res;
  }
  res = CheckExtensionsFormat(extensions);
  if (res != OK) {
    return res;
  }
  Serializer serializer;
  serializer.WriteUint(ct::V1, kVersionLengthInBytes);
  serializer.WriteUint(ct::CERTIFICATE_TIMESTAMP, kSignatureTypeLengthInBytes);
  serializer.WriteUint(timestamp, kTimestampLengthInBytes);
  serializer.WriteUint(ct::X_JSON_ENTRY, kLogEntryTypeLengthInBytes);
  serializer.WriteVarBytes(json, kMaxCertificateLength);
  serializer.WriteVarBytes(extensions, kMaxExtensionsLength);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeSCTSignatureInputV1(
    const SignedCertificateTimestamp& sct, const LogEntry& entry,
    string* result) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      return SerializeV1CertSCTSignatureInput(
          sct.timestamp(), entry.x509_entry().leaf_certificate(),
          sct.extensions(), result);
    case ct::PRECERT_ENTRY:
      return SerializeV1PrecertSCTSignatureInput(
          sct.timestamp(), entry.precert_entry().pre_cert().issuer_key_hash(),
          entry.precert_entry().pre_cert().tbs_certificate(), sct.extensions(),
          result);
    case ct::X_JSON_ENTRY:
      CHECK(entry.has_x_json_entry());
      *result = entry.x_json_entry().json();
      return OK;
    default:
      return INVALID_ENTRY_TYPE;
  }
}

// static
Serializer::SerializeResult Serializer::SerializeSCTSignatureInputV2(
    const SignedCertificateTimestamp& sct, const LogEntry& entry,
    string* result) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      return SerializeV2CertSCTSignatureInput(
          sct.timestamp(), entry.x509_entry().cert_info().issuer_key_hash(),
          entry.x509_entry().cert_info().tbs_certificate(),
          sct.sct_extension(), result);
    case ct::PRECERT_ENTRY_V2:
      return SerializeV2PrecertSCTSignatureInput(
          sct.timestamp(), entry.precert_entry().cert_info().issuer_key_hash(),
          entry.precert_entry().cert_info().tbs_certificate(),
          sct.sct_extension(), result);
    case ct::X_JSON_ENTRY:
      CHECK(entry.has_x_json_entry());
      *result = entry.x_json_entry().json();
      return OK;
    default:
      return INVALID_ENTRY_TYPE;
  }
}

// static
Serializer::SerializeResult Serializer::SerializeSCTSignatureInput(
    const SignedCertificateTimestamp& sct, const LogEntry& entry,
    string* result) {
  if (sct.version() == ct::V1) {
    return SerializeSCTSignatureInputV1(sct, entry, result);
  } else if (sct.version() == ct::V2) {
    return SerializeSCTSignatureInputV2(sct, entry, result);
  }

  return UNSUPPORTED_VERSION;
}

// static
Serializer::SerializeResult Serializer::SerializeV1CertSCTMerkleTreeLeaf(
    uint64_t timestamp, const string& certificate, const string& extensions,
    string* result) {
  SerializeResult res = CheckCertificateFormat(certificate);
  if (res != OK)
    return res;
  res = CheckExtensionsFormat(extensions);
  if (res != OK)
    return res;
  Serializer serializer;
  serializer.WriteUint(ct::V1, kVersionLengthInBytes);
  serializer.WriteUint(ct::TIMESTAMPED_ENTRY, kMerkleLeafTypeLengthInBytes);
  serializer.WriteUint(timestamp, kTimestampLengthInBytes);
  serializer.WriteUint(ct::X509_ENTRY, kLogEntryTypeLengthInBytes);
  serializer.WriteVarBytes(certificate, kMaxCertificateLength);
  serializer.WriteVarBytes(extensions, kMaxExtensionsLength);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeV1PrecertSCTMerkleTreeLeaf(
    uint64_t timestamp, const string& issuer_key_hash,
    const string& tbs_certificate, const string& extensions, string* result) {
  SerializeResult res = CheckCertificateFormat(tbs_certificate);
  if (res != OK)
    return res;
  res = CheckKeyHashFormat(issuer_key_hash);
  if (res != OK)
    return res;
  res = CheckExtensionsFormat(extensions);
  if (res != OK)
    return res;
  Serializer serializer;
  serializer.WriteUint(ct::V1, kVersionLengthInBytes);
  serializer.WriteUint(ct::TIMESTAMPED_ENTRY, kMerkleLeafTypeLengthInBytes);
  serializer.WriteUint(timestamp, kTimestampLengthInBytes);
  serializer.WriteUint(ct::PRECERT_ENTRY, kLogEntryTypeLengthInBytes);
  serializer.WriteFixedBytes(issuer_key_hash);
  serializer.WriteVarBytes(tbs_certificate, kMaxCertificateLength);
  serializer.WriteVarBytes(extensions, kMaxExtensionsLength);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeV2CertSCTMerkleTreeLeaf(
    uint64_t timestamp, const string& issuer_key_hash,
    const string& tbs_certificate,
    const RepeatedPtrField<SctExtension>& sct_extension, string* result) {
  SerializeResult res = CheckCertificateFormat(tbs_certificate);
  if (res != OK) {
    return res;
  }
  res = CheckSctExtensionsFormat(sct_extension);
  if (res != OK) {
    return res;
  }
  Serializer serializer;
  serializer.WriteUint(ct::V2, kVersionLengthInBytes);
  serializer.WriteUint(ct::TIMESTAMPED_ENTRY, kMerkleLeafTypeLengthInBytes);
  serializer.WriteUint(timestamp, kTimestampLengthInBytes);
  serializer.WriteUint(ct::X509_ENTRY, kLogEntryTypeLengthInBytes);
  serializer.WriteFixedBytes(issuer_key_hash);
  serializer.WriteVarBytes(tbs_certificate, kMaxCertificateLength);
  serializer.WriteSctExtension(sct_extension);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeV1XJsonSCTMerkleTreeLeaf(
    uint64_t timestamp, const string& json, const string& extensions,
    string* result) {
  CHECK_NOTNULL(result);
  // TODO(alcutter): CheckJsonFormat()?
  SerializeResult res = CheckCertificateFormat(json);
  if (res != OK) {
    return res;
  }
  res = CheckExtensionsFormat(extensions);
  if (res != OK) {
    return res;
  }
  Serializer serializer;
  serializer.WriteUint(ct::V1, kVersionLengthInBytes);
  serializer.WriteUint(ct::TIMESTAMPED_ENTRY, kMerkleLeafTypeLengthInBytes);
  serializer.WriteUint(timestamp, kTimestampLengthInBytes);
  serializer.WriteUint(ct::X_JSON_ENTRY, kLogEntryTypeLengthInBytes);
  serializer.WriteVarBytes(json, kMaxCertificateLength);
  serializer.WriteVarBytes(extensions, kMaxExtensionsLength);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeV2PrecertSCTMerkleTreeLeaf(
    uint64_t timestamp, const string& issuer_key_hash,
    const string& tbs_certificate,
    const google::protobuf::RepeatedPtrField<ct::SctExtension>& sct_extension,
    string* result) {
  SerializeResult res = CheckCertificateFormat(tbs_certificate);
  if (res != OK) {
    return res;
  }
  res = CheckKeyHashFormat(issuer_key_hash);
  if (res != OK) {
    return res;
  }
  res = CheckSctExtensionsFormat(sct_extension);
  if (res != OK) {
    return res;
  }
  Serializer serializer;
  serializer.WriteUint(ct::V2, kVersionLengthInBytes);
  serializer.WriteUint(ct::TIMESTAMPED_ENTRY, kMerkleLeafTypeLengthInBytes);
  serializer.WriteUint(timestamp, kTimestampLengthInBytes);
  serializer.WriteUint(ct::PRECERT_ENTRY_V2, kLogEntryTypeLengthInBytes);
  serializer.WriteFixedBytes(issuer_key_hash);
  serializer.WriteVarBytes(tbs_certificate, kMaxCertificateLength);
  serializer.WriteSctExtension(sct_extension);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeSCTMerkleTreeLeafV1(
    const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
    string* result) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      return SerializeV1CertSCTMerkleTreeLeaf(
          sct.timestamp(), entry.x509_entry().leaf_certificate(),
          sct.extensions(), result);
    case ct::PRECERT_ENTRY:
      return SerializeV1PrecertSCTMerkleTreeLeaf(
          sct.timestamp(), entry.precert_entry().pre_cert().issuer_key_hash(),
          entry.precert_entry().pre_cert().tbs_certificate(), sct.extensions(),
          result);
    case ct::X_JSON_ENTRY:
      return SerializeV1XJsonSCTMerkleTreeLeaf(sct.timestamp(),
                                               entry.x_json_entry().json(),
                                               sct.extensions(), result);
    default:
      return INVALID_ENTRY_TYPE;
  }
}

// static
Serializer::SerializeResult Serializer::SerializeSCTMerkleTreeLeafV2(
    const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
    string* result) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      return SerializeV2CertSCTMerkleTreeLeaf(
          sct.timestamp(), entry.x509_entry().cert_info().issuer_key_hash(),
          entry.x509_entry().cert_info().tbs_certificate(),
          sct.sct_extension(), result);
    case ct::PRECERT_ENTRY_V2:
      return SerializeV2PrecertSCTMerkleTreeLeaf(
          sct.timestamp(), entry.precert_entry().cert_info().issuer_key_hash(),
          entry.precert_entry().cert_info().tbs_certificate(),
          sct.sct_extension(), result);
    case ct::X_JSON_ENTRY:
      // TODO(mhs): Might be same as V1 but not supported yet
      LOG(FATAL) << "xjson not yet supported in V2";
      break;
    default:
      return INVALID_ENTRY_TYPE;
  }
}

// static
Serializer::SerializeResult Serializer::SerializeSCTMerkleTreeLeaf(
    const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
    string* result) {
  if (sct.version() == ct::V1) {
    return SerializeSCTMerkleTreeLeafV1(sct, entry, result);
  } else if (sct.version() == ct::V2) {
    return SerializeSCTMerkleTreeLeafV2(sct, entry, result);
  }

  return UNSUPPORTED_VERSION;
}

// static
Serializer::SerializeResult Serializer::SerializeV1STHSignatureInput(
    uint64_t timestamp, int64_t tree_size, const string& root_hash,
    string* result) {
  CHECK_GE(tree_size, 0);
  if (root_hash.size() != 32)
    return INVALID_HASH_LENGTH;
  Serializer serializer;
  serializer.WriteUint(ct::V1, kVersionLengthInBytes);
  serializer.WriteUint(ct::TREE_HEAD, kSignatureTypeLengthInBytes);
  serializer.WriteUint(timestamp, kTimestampLengthInBytes);
  serializer.WriteUint(tree_size, 8);
  serializer.WriteFixedBytes(root_hash);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeV2STHSignatureInput(
    uint64_t timestamp, int64_t tree_size, const string& root_hash,
    const RepeatedPtrField<SthExtension>& sth_extension, const string& log_id,
    string* result) {
  CHECK_GE(tree_size, 0);
  if (root_hash.size() != 32) {
    return INVALID_HASH_LENGTH;
  }
  SerializeResult res = CheckSthExtensionsFormat(sth_extension);
  if (res != OK) {
    return res;
  }
  if (log_id.size() != kKeyIDLengthInBytes) {
    return INVALID_KEYID_LENGTH;
  }
  Serializer serializer;
  serializer.WriteUint(ct::V2, kVersionLengthInBytes);
  serializer.WriteUint(ct::TREE_HEAD, kSignatureTypeLengthInBytes);
  serializer.WriteFixedBytes(log_id);
  serializer.WriteUint(timestamp, kTimestampLengthInBytes);
  serializer.WriteUint(tree_size, 8);
  serializer.WriteFixedBytes(root_hash);
  // V2 STH can have multiple extensions
  serializer.WriteUint(sth_extension.size(), 2);
  for (auto it = sth_extension.begin(); it != sth_extension.end(); ++it) {
    serializer.WriteUint(it->sth_extension_type(), 2);
    serializer.WriteVarBytes(it->sth_extension_data(), kMaxExtensionsLength);
  }

  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeSTHSignatureInput(
    const ct::SignedTreeHead& sth, string* result) {
  if (sth.version() == ct::V1) {
    return SerializeV1STHSignatureInput(sth.timestamp(), sth.tree_size(),
                                        sth.sha256_root_hash(), result);
  } else if (sth.version() == ct::V2) {
    return SerializeV2STHSignatureInput(sth.timestamp(), sth.tree_size(),
                                        sth.sha256_root_hash(),
                                        sth.sth_extension(), sth.id().key_id(),
                                        result);
  } else {
    return UNSUPPORTED_VERSION;
  }
}


Serializer::SerializeResult Serializer::WriteSCTV1(
    const SignedCertificateTimestamp& sct) {
  CHECK(sct.version() == ct::V1);
  SerializeResult res = CheckExtensionsFormat(sct.extensions());
  if (res != OK) {
    return res;
  }
  if (sct.id().key_id().size() != kKeyIDLengthInBytes) {
    return INVALID_KEYID_LENGTH;
  }
  WriteUint(sct.version(), kVersionLengthInBytes);
  WriteFixedBytes(sct.id().key_id());
  WriteUint(sct.timestamp(), kTimestampLengthInBytes);
  WriteVarBytes(sct.extensions(), kMaxExtensionsLength);
  return WriteDigitallySigned(sct.signature());
}

Serializer::SerializeResult Serializer::WriteSCTV2(
    const SignedCertificateTimestamp& sct) {
  CHECK(sct.version() == ct::V2);
  SerializeResult res = CheckSctExtensionsFormat(sct.sct_extension());
  if (res != OK) {
    return res;
  }
  if (sct.id().key_id().size() != kKeyIDLengthInBytes) {
    return INVALID_KEYID_LENGTH;
  }
  WriteUint(sct.version(), kVersionLengthInBytes);
  WriteFixedBytes(sct.id().key_id());
  WriteUint(sct.timestamp(), kTimestampLengthInBytes);
  // V2 SCT can have a number of extensions. They must be ordered by type
  // but we already checked that above.
  WriteSctExtension(sct.sct_extension());
  return WriteDigitallySigned(sct.signature());
}

// static
Serializer::SerializeResult Serializer::SerializeSCT(
    const SignedCertificateTimestamp& sct, string* result) {
  Serializer serializer;
  SerializeResult res = UNSUPPORTED_VERSION;

  switch (sct.version()) {
    case ct::V1:
      res = serializer.WriteSCTV1(sct);
      break;
    case ct::V2:
      res = serializer.WriteSCTV2(sct);
      break;
    default:
      res = UNSUPPORTED_VERSION;
  }
  if (res != OK) {
    return res;
  }
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeSCTList(
    const SignedCertificateTimestampList& sct_list, string* result) {
  if (sct_list.sct_list_size() == 0) {
    return EMPTY_LIST;
  }
  return SerializeList(sct_list.sct_list(), kMaxSerializedSCTLength,
                       kMaxSCTListLength, result);
}

// static
Serializer::SerializeResult Serializer::SerializeX509Chain(
    const ct::X509ChainEntry& entry, std::string* result) {
  return SerializeX509ChainV1(entry.certificate_chain(), result);
}

// static
Serializer::SerializeResult Serializer::SerializeX509ChainV1(
    const repeated_string& certificate_chain, std::string* result) {
  return SerializeList(certificate_chain, kMaxCertificateLength,
                       kMaxCertificateChainLength, result);
}

// static
Serializer::SerializeResult Serializer::SerializePrecertChainEntry(
    const ct::PrecertChainEntry& entry, std::string* result) {
  return SerializePrecertChainEntry(entry.pre_certificate(),
                                    entry.precertificate_chain(), result);
}

// static
Serializer::SerializeResult Serializer::SerializePrecertChainEntry(
    const std::string& pre_certificate,
    const repeated_string& precertificate_chain, std::string* result) {
  Serializer serializer;
  if (pre_certificate.size() > kMaxCertificateLength)
    return CERTIFICATE_TOO_LONG;
  if (pre_certificate.empty())
    return EMPTY_CERTIFICATE;

  serializer.WriteVarBytes(pre_certificate, kMaxCertificateLength);

  SerializeResult res =
      serializer.WriteList(precertificate_chain, kMaxCertificateLength,
                           kMaxCertificateChainLength);
  if (res != OK) {
    return res;
  }
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeDigitallySigned(
    const DigitallySigned& sig, string* result) {
  Serializer serializer;
  SerializeResult res = serializer.WriteDigitallySigned(sig);
  if (res != OK) {
    return res;
  }
  result->assign(serializer.SerializedString());
  return OK;
}

// static
// TODO(mhs): Might need V2 version but I don't see any usages that aren't
// tests so possibly not used.
Serializer::SerializeResult Serializer::SerializeV1SignedEntryWithType(
    const ct::LogEntry entry, std::string* result) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      LOG_IF(INFO, entry.x509_entry().has_cert_info())
          << "Saw a V2 X509 entry when serializing v1";
      return SerializeV1SignedCertEntryWithType(
          entry.x509_entry().leaf_certificate(), result);
    case ct::PRECERT_ENTRY:
      return SerializeV1SignedPrecertEntryWithType(
          entry.precert_entry().pre_cert().issuer_key_hash(),
          entry.precert_entry().pre_cert().tbs_certificate(), result);
    case ct::PRECERT_ENTRY_V2:
      LOG(INFO) << "Saw a PRECERT_ENTRY_V2 when serializing v1 signed type";
      return INVALID_ENTRY_TYPE;
    case ct::X_JSON_ENTRY:
      return SerializeV1SignedXJsonEntryWithType(entry.x_json_entry().json(),
                                                 result);
    default:
      return INVALID_ENTRY_TYPE;
  }
}

// static
Serializer::SerializeResult Serializer::SerializeV1SignedCertEntryWithType(
    const std::string& leaf_certificate, std::string* result) {
  SerializeResult res = CheckCertificateFormat(leaf_certificate);
  if (res != OK)
    return res;
  Serializer serializer;
  serializer.WriteUint(ct::X509_ENTRY, kLogEntryTypeLengthInBytes);
  serializer.WriteVarBytes(leaf_certificate, kMaxCertificateLength);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeV1SignedPrecertEntryWithType(
    const std::string& issuer_key_hash, const std::string& tbs_certificate,
    std::string* result) {
  SerializeResult res = CheckCertificateFormat(tbs_certificate);
  if (res != OK)
    return res;
  res = CheckKeyHashFormat(issuer_key_hash);
  if (res != OK)
    return res;
  Serializer serializer;
  serializer.WriteUint(ct::PRECERT_ENTRY, kLogEntryTypeLengthInBytes);
  serializer.WriteFixedBytes(issuer_key_hash);
  serializer.WriteVarBytes(tbs_certificate, kMaxCertificateLength);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeV2SignedPrecertEntryWithType(
    const std::string& issuer_key_hash, const std::string& tbs_certificate,
    std::string* result) {
  SerializeResult res = CheckCertificateFormat(tbs_certificate);
  if (res != OK) {
    return res;
  }
  res = CheckKeyHashFormat(issuer_key_hash);
  if (res != OK) {
    return res;
  }
  Serializer serializer;
  serializer.WriteUint(ct::PRECERT_ENTRY_V2, kLogEntryTypeLengthInBytes);
  serializer.WriteFixedBytes(issuer_key_hash);
  serializer.WriteVarBytes(tbs_certificate, kMaxCertificateLength);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeV1SignedXJsonEntryWithType(
    const std::string& json, std::string* result) {
  CHECK_NOTNULL(result);
  // TODO(alcutter: CheckJsonFormat()?
  SerializeResult res = CheckCertificateFormat(json);
  if (res != OK) {
    return res;
  }
  Serializer serializer;
  serializer.WriteUint(ct::X_JSON_ENTRY, kLogEntryTypeLengthInBytes);
  serializer.WriteVarBytes(json, kMaxCertificateLength);
  result->assign(serializer.SerializedString());
  return OK;
}

void Serializer::WriteFixedBytes(const string& in) {
  output_.append(in);
}

void Serializer::WriteVarBytes(const string& in, size_t max_length) {
  CHECK_LE(in.size(), max_length);

  size_t prefix_length = PrefixLength(max_length);
  WriteUint(in.size(), prefix_length);
  WriteFixedBytes(in);
}

// This does not enforce extension ordering, which must be done separately.
void Serializer::WriteSctExtension(
    const RepeatedPtrField<SctExtension>& extension) {
  WriteUint(extension.size(), 2);
  for (auto it = extension.begin(); it != extension.end(); ++it) {
    WriteUint(it->sct_extension_type(), 2);
    WriteVarBytes(it->sct_extension_data(), kMaxExtensionsLength);
  }
}

// static
size_t Serializer::SerializedListLength(const repeated_string& in,
                                        size_t max_elem_length,
                                        size_t max_total_length) {
  size_t elem_prefix_length = PrefixLength(max_elem_length);
  size_t total_length = 0;

  for (int i = 0; i < in.size(); ++i) {
    if (in.Get(i).size() > max_elem_length ||
        max_total_length - total_length < elem_prefix_length ||
        max_total_length - total_length - elem_prefix_length <
            in.Get(i).size())
      return 0;

    total_length += elem_prefix_length + in.Get(i).size();
  }

  return total_length + PrefixLength(max_total_length);
}

// static
Serializer::SerializeResult Serializer::SerializeList(
    const repeated_string& in, size_t max_elem_length, size_t max_total_length,
    string* result) {
  Serializer serializer;
  SerializeResult res =
      serializer.WriteList(in, max_elem_length, max_total_length);
  if (res != OK)
    return res;
  result->assign(serializer.SerializedString());
  return OK;
}

Serializer::SerializeResult Serializer::WriteList(const repeated_string& in,
                                                  size_t max_elem_length,
                                                  size_t max_total_length) {
  for (int i = 0; i < in.size(); ++i) {
    if (in.Get(i).empty())
      return EMPTY_ELEM_IN_LIST;
    if (in.Get(i).size() > max_elem_length)
      return LIST_ELEM_TOO_LONG;
  }
  size_t length = SerializedListLength(in, max_elem_length, max_total_length);
  if (length == 0)
    return LIST_TOO_LONG;
  size_t prefix_length = PrefixLength(max_total_length);
  CHECK_GE(length, prefix_length);

  WriteUint(length - prefix_length, prefix_length);

  for (int i = 0; i < in.size(); ++i)
    WriteVarBytes(in.Get(i), max_elem_length);
  return OK;
}

Serializer::SerializeResult Serializer::WriteDigitallySigned(
    const DigitallySigned& sig) {
  SerializeResult res = CheckSignatureFormat(sig);
  if (res != OK)
    return res;
  WriteUint(sig.hash_algorithm(), kHashAlgorithmLengthInBytes);
  WriteUint(sig.sig_algorithm(), kSigAlgorithmLengthInBytes);
  WriteVarBytes(sig.signature(), kMaxSignatureLength);
  return OK;
}

Serializer::SerializeResult Serializer::CheckKeyHashFormat(
    const string& key_hash) {
  if (key_hash.size() != kKeyHashLengthInBytes)
    return INVALID_HASH_LENGTH;
  return OK;
}

Serializer::SerializeResult Serializer::CheckSignatureFormat(
    const DigitallySigned& sig) {
  // This is just DCHECKED upon setting, so check again.
  if (!DigitallySigned_HashAlgorithm_IsValid(sig.hash_algorithm()))
    return INVALID_HASH_ALGORITHM;
  if (!DigitallySigned_SignatureAlgorithm_IsValid(sig.sig_algorithm()))
    return INVALID_SIGNATURE_ALGORITHM;
  if (sig.signature().size() > kMaxSignatureLength)
    return SIGNATURE_TOO_LONG;
  return OK;
}

Serializer::SerializeResult Serializer::CheckCertificateFormat(
    const string& cert) {
  if (cert.empty())
    return EMPTY_CERTIFICATE;
  if (cert.size() > kMaxCertificateLength)
    return CERTIFICATE_TOO_LONG;
  return OK;
}

Serializer::SerializeResult Serializer::CheckExtensionsFormat(
    const string& extensions) {
  if (extensions.size() > kMaxExtensionsLength)
    return EXTENSIONS_TOO_LONG;
  return OK;
}

// Checks the (v2) STH extensions are correct. The RFC defines that there can
// be up to 65534 of them and each one can contain up to 65535 bytes.
// They must be in ascending order of extension type.
Serializer::SerializeResult Serializer::CheckSthExtensionsFormat(
    const RepeatedPtrField<SthExtension>& extension) {
  if (extension.size() > kMaxV2ExtensionsCount) {
    return EXTENSIONS_TOO_LONG;
  }

  int32_t last_type_seen = 0;

  for (auto it = extension.begin(); it != extension.end(); ++it) {
    if (it->sth_extension_type() > kMaxV2ExtensionType) {
      return INVALID_ENTRY_TYPE;
    }

    if (it->sth_extension_data().size() > kMaxExtensionsLength) {
      return EXTENSIONS_TOO_LONG;
    }

    if (it->sth_extension_type() < last_type_seen) {
      // It's out of order - reject
      return EXTENSIONS_NOT_ORDERED;
    }

    last_type_seen = it->sth_extension_type();
  }

  return OK;
}

// Checks the (v2) SCT extensions are correct. The RFC defines that there can
// be up to 65534 of them and each one can contain up to 65535 bytes. They
// must be in ascending order of extension type
Serializer::SerializeResult Serializer::CheckSctExtensionsFormat(
    const RepeatedPtrField<SctExtension>& extension) {
  if (extension.size() > kMaxV2ExtensionsCount) {
    return EXTENSIONS_TOO_LONG;
  }

  int32_t last_type_seen = 0;

  for (auto it = extension.begin(); it != extension.end(); ++it) {
    if (it->sct_extension_data().size() > kMaxExtensionsLength) {
      return EXTENSIONS_TOO_LONG;
    }

    if (it->sct_extension_type() > kMaxV2ExtensionType) {
      return INVALID_ENTRY_TYPE;
    }

    if (it->sct_extension_type() < last_type_seen) {
      // It's out of order - reject
      return EXTENSIONS_NOT_ORDERED;
    }

    last_type_seen = it->sct_extension_type();
  }

  return OK;
}

Serializer::SerializeResult Serializer::CheckChainFormat(
    const repeated_string& chain) {
  for (int i = 0; i < chain.size(); ++i) {
    SerializeResult res = CheckCertificateFormat(chain.Get(i));
    if (res != OK)
      return res;
  }
  size_t total_length =
      Serializer::SerializedListLength(chain, kMaxCertificateLength,
                                       kMaxCertificateChainLength);
  if (total_length == 0)
    return CERTIFICATE_CHAIN_TOO_LONG;
  return OK;
}

// static
Serializer::SerializeResult Serializer::CheckX509ChainEntryFormatV1(
    const X509ChainEntry& entry) {
  const SerializeResult res = CheckCertificateFormat(entry.leaf_certificate());
  if (res != OK) {
    return res;
  }
  return CheckChainFormat(entry.certificate_chain());
}

// static
Serializer::SerializeResult Serializer::CheckX509ChainEntryFormatV2(
    const X509ChainEntry& entry) {
  const SerializeResult res =
      CheckCertificateFormat(entry.cert_info().tbs_certificate());
  if (res != OK) {
    return res;
  }
  return CheckChainFormat(entry.certificate_chain());
}

// static
Serializer::SerializeResult Serializer::CheckPrecertChainEntryFormatV1(
    const PrecertChainEntry& entry) {
  SerializeResult res = CheckCertificateFormat(entry.pre_certificate());
  if (res != OK) {
    return res;
  }
  res = CheckCertificateFormat(entry.pre_cert().tbs_certificate());
  if (res != OK) {
    return res;
  }
  res = CheckKeyHashFormat(entry.pre_cert().issuer_key_hash());
  if (res != OK) {
    return res;
  }
  return CheckChainFormat(entry.precertificate_chain());
}

// static
Serializer::SerializeResult Serializer::CheckPrecertChainEntryFormatV2(
    const PrecertChainEntry& entry) {
  SerializeResult res = CheckCertificateFormat(entry.pre_certificate());
  if (res != OK) {
    return res;
  }
  res = CheckCertificateFormat(entry.cert_info().tbs_certificate());
  if (res != OK) {
    return res;
  }
  res = CheckKeyHashFormat(entry.cert_info().issuer_key_hash());
  if (res != OK) {
    return res;
  }
  return CheckChainFormat(entry.precertificate_chain());
}

const size_t Deserializer::kV2ExtensionCountLengthInBytes = 2;
const size_t Deserializer::kV2ExtensionTypeLengthInBytes = 2;

Deserializer::Deserializer(const string& input)
    : current_pos_(input.data()), bytes_remaining_(input.size()) {
}

Deserializer::DeserializeResult Deserializer::ReadSCTV1(
    SignedCertificateTimestamp* sct) {
  sct->set_version(ct::V1);
  if (!ReadFixedBytes(Serializer::kKeyIDLengthInBytes,
                      sct->mutable_id()->mutable_key_id())) {
    return INPUT_TOO_SHORT;
  }
  // V1 encoding.
  uint64_t timestamp = 0;
  if (!ReadUint(Serializer::kTimestampLengthInBytes, &timestamp)) {
    return INPUT_TOO_SHORT;
  }
  sct->set_timestamp(timestamp);
  string extensions;
  if (!ReadVarBytes(Serializer::kMaxExtensionsLength, &extensions)) {
    // In theory, could also be an invalid length prefix, but not if
    // length limits follow byte boundaries.
    return INPUT_TOO_SHORT;
  }
  return ReadDigitallySigned(sct->mutable_signature());
}

Deserializer::DeserializeResult Deserializer::ReadSCTV2(
    SignedCertificateTimestamp* sct) {
  sct->set_version(ct::V2);
  if (!ReadFixedBytes(Serializer::kKeyIDLengthInBytes,
                      sct->mutable_id()->mutable_key_id())) {
    return INPUT_TOO_SHORT;
  }
  // V2 encoding.
  uint64_t timestamp = 0;
  if (!ReadUint(Serializer::kTimestampLengthInBytes, &timestamp)) {
    return INPUT_TOO_SHORT;
  }
  sct->set_timestamp(timestamp);
  // Extensions are handled differently for V2
  Deserializer::DeserializeResult res =
      ReadSctExtension(sct->mutable_sct_extension());
  if (res != OK) {
    return res;
  }
  return ReadDigitallySigned(sct->mutable_signature());
}

Deserializer::DeserializeResult Deserializer::ReadSCT(
    SignedCertificateTimestamp* sct) {
  int version;
  if (!ReadUint(Serializer::kVersionLengthInBytes, &version)) {
    return INPUT_TOO_SHORT;
  }
  if (!Version_IsValid(version) || (version != ct::V1 && version != ct::V2)) {
    return UNSUPPORTED_VERSION;
  }

  switch (version) {
    case ct::V1:
      return ReadSCTV1(sct);
      break;

    case ct::V2:

      return ReadSCTV2(sct);
      break;

    default:
      return UNSUPPORTED_VERSION;
  }
}

// static
Deserializer::DeserializeResult Deserializer::DeserializeSCT(
    const string& in, SignedCertificateTimestamp* sct) {
  Deserializer deserializer(in);
  DeserializeResult res = deserializer.ReadSCT(sct);
  if (res != OK) {
    return res;
  }
  if (!deserializer.ReachedEnd()) {
    return INPUT_TOO_LONG;
  }
  return OK;
}

// static
Deserializer::DeserializeResult Deserializer::DeserializeSCTList(
    const string& in, SignedCertificateTimestampList* sct_list) {
  sct_list->clear_sct_list();
  DeserializeResult res = DeserializeList(in, Serializer::kMaxSCTListLength,
                                          Serializer::kMaxSerializedSCTLength,
                                          sct_list->mutable_sct_list());
  if (res != OK)
    return res;
  if (sct_list->sct_list_size() == 0)
    return EMPTY_LIST;
  return OK;
}

// static
Deserializer::DeserializeResult Deserializer::DeserializeDigitallySigned(
    const string& in, DigitallySigned* sig) {
  Deserializer deserializer(in);
  DeserializeResult res = deserializer.ReadDigitallySigned(sig);
  if (res != OK)
    return res;
  if (!deserializer.ReachedEnd())
    return INPUT_TOO_LONG;
  return OK;
}

// static
Deserializer::DeserializeResult Deserializer::DeserializeX509Chain(
    const std::string& in, X509ChainEntry* x509_chain_entry) {
  // Empty list is ok.
  x509_chain_entry->clear_certificate_chain();
  return DeserializeList(in, Serializer::kMaxCertificateChainLength,
                         Serializer::kMaxCertificateLength,
                         x509_chain_entry->mutable_certificate_chain());
}

// static
Deserializer::DeserializeResult Deserializer::DeserializePrecertChainEntry(
    const std::string& in, ct::PrecertChainEntry* precert_chain_entry) {
  Deserializer deserializer(in);
  if (!deserializer.ReadVarBytes(
          Serializer::kMaxCertificateLength,
          precert_chain_entry->mutable_pre_certificate()))
    return INPUT_TOO_SHORT;
  precert_chain_entry->clear_precertificate_chain();
  DeserializeResult res = deserializer.ReadList(
      Serializer::kMaxCertificateChainLength,
      Serializer::kMaxCertificateLength,
      precert_chain_entry->mutable_precertificate_chain());
  if (res != OK)
    return res;
  if (!deserializer.ReachedEnd())
    return INPUT_TOO_LONG;
  return OK;
}

bool Deserializer::ReadFixedBytes(size_t bytes, string* result) {
  if (bytes_remaining_ < bytes)
    return false;
  result->assign(current_pos_, bytes);
  current_pos_ += bytes;
  bytes_remaining_ -= bytes;
  return true;
}

bool Deserializer::ReadLengthPrefix(size_t max_length, size_t* result) {
  size_t prefix_length = Serializer::PrefixLength(max_length);
  size_t length;
  if (!ReadUint(prefix_length, &length) || length > max_length)
    return false;
  *result = length;
  return true;
}

bool Deserializer::ReadVarBytes(size_t max_length, string* result) {
  size_t length;
  if (!ReadLengthPrefix(max_length, &length))
    return false;
  return ReadFixedBytes(length, result);
}

// static
Deserializer::DeserializeResult Deserializer::DeserializeList(
    const string& in, size_t max_total_length, size_t max_elem_length,
    repeated_string* out) {
  Deserializer deserializer(in);
  DeserializeResult res =
      deserializer.ReadList(max_total_length, max_elem_length, out);
  if (res != OK)
    return res;
  if (!deserializer.ReachedEnd())
    return INPUT_TOO_LONG;
  return OK;
}

Deserializer::DeserializeResult Deserializer::ReadList(size_t max_total_length,
                                                       size_t max_elem_length,
                                                       repeated_string* out) {
  string serialized_list;
  if (!ReadVarBytes(max_total_length, &serialized_list))
    // TODO(ekasper): could also be a length that's too large, if
    // length limits don't follow byte boundaries.
    return INPUT_TOO_SHORT;
  if (!ReachedEnd())
    return INPUT_TOO_LONG;

  Deserializer list_reader(serialized_list);
  while (!list_reader.ReachedEnd()) {
    string elem;
    if (!list_reader.ReadVarBytes(max_elem_length, &elem))
      return INVALID_LIST_ENCODING;
    if (elem.empty())
      return EMPTY_ELEM_IN_LIST;
    *(out->Add()) = elem;
  }
  return OK;
}

Deserializer::DeserializeResult Deserializer::ReadSctExtension(
    RepeatedPtrField<SctExtension>* extension) {
  uint32_t ext_count;
  if (!ReadUint(kV2ExtensionCountLengthInBytes, &ext_count)) {
    return INPUT_TOO_SHORT;
  }

  if (ext_count > Serializer::kMaxV2ExtensionsCount) {
    return EXTENSIONS_TOO_LONG;
  }

  for (int ext = 0; ext < ext_count; ++ext) {
    uint32_t ext_type;
    if (!ReadUint(kV2ExtensionTypeLengthInBytes, &ext_type)) {
      return INPUT_TOO_SHORT;
    }

    string ext_data;
    if (!ReadVarBytes(Serializer::kMaxExtensionsLength, &ext_data)) {
      return INPUT_TOO_SHORT;
    }

    SctExtension* new_ext = extension->Add();
    new_ext->set_sct_extension_type(ext_type);
    new_ext->set_sct_extension_data(ext_data);
  }

  // This makes sure they're correctly ordered (See RFC section 5.3)
  return Serializer::CheckSctExtensionsFormat(*extension) ==
                 Serializer::SerializeResult::OK
             ? OK
             : EXTENSIONS_NOT_ORDERED;
}

Deserializer::DeserializeResult Deserializer::ReadDigitallySigned(
    DigitallySigned* sig) {
  int hash_algo = -1, sig_algo = -1;
  if (!ReadUint(Serializer::kHashAlgorithmLengthInBytes, &hash_algo))
    return INPUT_TOO_SHORT;
  if (!DigitallySigned_HashAlgorithm_IsValid(hash_algo))
    return INVALID_HASH_ALGORITHM;
  if (!ReadUint(Serializer::kSigAlgorithmLengthInBytes, &sig_algo))
    return INPUT_TOO_SHORT;
  if (!DigitallySigned_SignatureAlgorithm_IsValid(sig_algo))
    return INVALID_SIGNATURE_ALGORITHM;

  string sig_string;
  if (!ReadVarBytes(Serializer::kMaxSignatureLength, &sig_string))
    return INPUT_TOO_SHORT;
  sig->set_hash_algorithm(
      static_cast<DigitallySigned::HashAlgorithm>(hash_algo));
  sig->set_sig_algorithm(
      static_cast<DigitallySigned::SignatureAlgorithm>(sig_algo));
  sig->set_signature(sig_string);
  return OK;
}

Deserializer::DeserializeResult Deserializer::ReadExtensions(
    ct::TimestampedEntry* entry) {
  string extensions;
  if (!ReadVarBytes(Serializer::kMaxExtensionsLength, &extensions)) {
    return INPUT_TOO_SHORT;
  }
  CHECK_NOTNULL(entry)->set_extensions(extensions);
  return OK;
}

Deserializer::DeserializeResult Deserializer::ReadMerkleTreeLeafV1(
    ct::MerkleTreeLeaf* leaf) {
  leaf->set_version(ct::V1);

  unsigned int type;
  if (!ReadUint(Serializer::kMerkleLeafTypeLengthInBytes, &type)) {
    return INPUT_TOO_SHORT;
  }
  if (type != ct::TIMESTAMPED_ENTRY) {
    return UNKNOWN_LEAF_TYPE;
  }
  leaf->set_type(ct::TIMESTAMPED_ENTRY);

  ct::TimestampedEntry* const entry = leaf->mutable_timestamped_entry();

  uint64_t timestamp;
  if (!ReadUint(Serializer::kTimestampLengthInBytes, &timestamp)) {
    return INPUT_TOO_SHORT;
  }
  entry->set_timestamp(timestamp);

  unsigned int entry_type;
  if (!ReadUint(Serializer::kLogEntryTypeLengthInBytes, &entry_type)) {
    return INPUT_TOO_SHORT;
  }

  CHECK(LogEntryType_IsValid(entry_type));
  entry->set_entry_type(static_cast<ct::LogEntryType>(entry_type));

  switch (entry_type) {
    case ct::X509_ENTRY: {
      string x509;
      if (!ReadVarBytes(Serializer::kMaxCertificateLength, &x509)) {
        return INPUT_TOO_SHORT;
      }
      entry->mutable_signed_entry()->set_x509(x509);
      return ReadExtensions(entry);
    }

    case ct::PRECERT_ENTRY: {
      string issuer_key_hash;
      if (!ReadFixedBytes(32, &issuer_key_hash)) {
        return INPUT_TOO_SHORT;
      }
      entry->mutable_signed_entry()->mutable_precert()->set_issuer_key_hash(
          issuer_key_hash);
      string tbs_certificate;
      if (!ReadVarBytes(Serializer::kMaxCertificateLength, &tbs_certificate)) {
        return INPUT_TOO_SHORT;
      }
      entry->mutable_signed_entry()->mutable_precert()->set_tbs_certificate(
          tbs_certificate);
      return ReadExtensions(entry);
    }

    case ct::X_JSON_ENTRY: {
      string json;
      if (!ReadVarBytes(Serializer::kMaxCertificateLength, &json)) {
        return INPUT_TOO_SHORT;
      }
      entry->mutable_signed_entry()->set_json(json);
      return ReadExtensions(entry);
    }

    case ct::UNKNOWN_ENTRY_TYPE: {
      // handled below.
      break;
    }
  }

  return UNKNOWN_LOGENTRY_TYPE;
}

Deserializer::DeserializeResult Deserializer::ReadMerkleTreeLeafV2(
    ct::MerkleTreeLeaf* leaf) {
  leaf->set_version(ct::V2);

  unsigned int type;
  if (!ReadUint(Serializer::kMerkleLeafTypeLengthInBytes, &type)) {
    return INPUT_TOO_SHORT;
  }
  if (type != ct::TIMESTAMPED_ENTRY) {
    return UNKNOWN_LEAF_TYPE;
  }
  leaf->set_type(ct::TIMESTAMPED_ENTRY);

  ct::TimestampedEntry* const entry = leaf->mutable_timestamped_entry();

  uint64_t timestamp;
  if (!ReadUint(Serializer::kTimestampLengthInBytes, &timestamp)) {
    return INPUT_TOO_SHORT;
  }
  entry->set_timestamp(timestamp);

  unsigned int entry_type;
  if (!ReadUint(Serializer::kLogEntryTypeLengthInBytes, &entry_type)) {
    return INPUT_TOO_SHORT;
  }

  CHECK(LogEntryType_IsValid(entry_type));
  entry->set_entry_type(static_cast<ct::LogEntryType>(entry_type));

  switch (entry_type) {
    // In V2 both X509 and Precert entries use CertInfo
    case ct::X509_ENTRY:
    case ct::PRECERT_ENTRY_V2: {
      string issuer_key_hash;
      if (!ReadFixedBytes(32, &issuer_key_hash)) {
        return INPUT_TOO_SHORT;
      }
      entry->mutable_signed_entry()->mutable_cert_info()->set_issuer_key_hash(
          issuer_key_hash);
      string tbs_certificate;
      if (!ReadVarBytes(Serializer::kMaxCertificateLength, &tbs_certificate)) {
        return INPUT_TOO_SHORT;
      }
      entry->mutable_signed_entry()->mutable_cert_info()->set_tbs_certificate(
          tbs_certificate);
      return ReadExtensions(entry);
    }

    case ct::X_JSON_ENTRY: {
      LOG(FATAL) << "xjson not yet supported by CT v2";
      break;
    }

    case ct::UNKNOWN_ENTRY_TYPE: {
      // handled below.
      break;
    }
  }

  return UNKNOWN_LOGENTRY_TYPE;
}

Deserializer::DeserializeResult Deserializer::ReadMerkleTreeLeaf(
    ct::MerkleTreeLeaf* leaf, Deserializer& des) {
  unsigned int version;
  if (!des.ReadUint(Serializer::kVersionLengthInBytes, &version)) {
    return INPUT_TOO_SHORT;
  }

  if (!Version_IsValid(version)) {
    return UNSUPPORTED_VERSION;
  }

  if (version == ct::V1) {
    return des.ReadMerkleTreeLeafV1(leaf);
  } else if (version == ct::V2) {
    return des.ReadMerkleTreeLeafV2(leaf);
  }

  return UNSUPPORTED_VERSION;
}

Deserializer::DeserializeResult Deserializer::DeserializeMerkleTreeLeaf(
    const std::string& in, ct::MerkleTreeLeaf* leaf) {
  Deserializer des(in);

  DeserializeResult ret = des.ReadMerkleTreeLeaf(leaf, des);

  if (ret != OK) {
    return ret;
  }

  if (!des.ReachedEnd()) {
    return INPUT_TOO_LONG;
  }

  return OK;
}
