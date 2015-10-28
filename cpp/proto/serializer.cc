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
using ct::Version_IsValid;
using ct::X509ChainEntry;
using std::string;

const size_t Serializer::kMaxCertificateLength = (1 << 24) - 1;
const size_t Serializer::kMaxCertificateChainLength = (1 << 24) - 1;
const size_t Serializer::kMaxSignatureLength = (1 << 16) - 1;
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
Serializer::SerializeResult Serializer::CheckLogEntryFormat(
    const LogEntry& entry) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      return CheckX509ChainEntryFormat(entry.x509_entry());
    case ct::PRECERT_ENTRY:
      return CheckPrecertChainEntryFormat(entry.precert_entry());
    default:
      return INVALID_ENTRY_TYPE;
  }
}

// static
string Serializer::LeafData(const LogEntry& entry) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      CHECK(entry.x509_entry().has_leaf_certificate())
          << "Missing leaf certificate";
      return entry.x509_entry().leaf_certificate();
    case ct::PRECERT_ENTRY:
      CHECK(entry.precert_entry().pre_cert().has_tbs_certificate())
          << "Missing tbs certificate";
      return entry.precert_entry().pre_cert().tbs_certificate();
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
Serializer::SerializeResult Serializer::SerializeSCTSignatureInput(
    const SignedCertificateTimestamp& sct, const LogEntry& entry,
    string* result) {
  if (sct.version() != ct::V1)
    return UNSUPPORTED_VERSION;
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
    default:
      return INVALID_ENTRY_TYPE;
  }
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
Serializer::SerializeResult Serializer::SerializeSCTMerkleTreeLeaf(
    const ct::SignedCertificateTimestamp& sct, const ct::LogEntry& entry,
    string* result) {
  if (sct.version() != ct::V1)
    return UNSUPPORTED_VERSION;
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
    default:
      return INVALID_ENTRY_TYPE;
  }
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
Serializer::SerializeResult Serializer::SerializeSTHSignatureInput(
    const ct::SignedTreeHead& sth, string* result) {
  if (sth.version() != ct::V1)
    return UNSUPPORTED_VERSION;
  return SerializeV1STHSignatureInput(sth.timestamp(), sth.tree_size(),
                                      sth.sha256_root_hash(), result);
}


Serializer::SerializeResult Serializer::WriteSCT(
    const SignedCertificateTimestamp& sct) {
  if (sct.version() != ct::V1)
    return UNSUPPORTED_VERSION;
  SerializeResult res = CheckExtensionsFormat(sct.extensions());
  if (res != OK)
    return res;
  if (sct.id().key_id().size() != kKeyIDLengthInBytes)
    return INVALID_KEYID_LENGTH;
  WriteUint(ct::V1, kVersionLengthInBytes);
  WriteFixedBytes(sct.id().key_id());
  WriteUint(sct.timestamp(), kTimestampLengthInBytes);
  WriteVarBytes(sct.extensions(), kMaxExtensionsLength);
  return WriteDigitallySigned(sct.signature());
}

// static
Serializer::SerializeResult Serializer::SerializeSCT(
    const SignedCertificateTimestamp& sct, string* result) {
  Serializer serializer;
  SerializeResult res = serializer.WriteSCT(sct);
  if (res != OK)
    return res;
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeSCTList(
    const SignedCertificateTimestampList& sct_list, string* result) {
  if (sct_list.sct_list_size() == 0)
    return EMPTY_LIST;
  return SerializeList(sct_list.sct_list(), kMaxSerializedSCTLength,
                       kMaxSCTListLength, result);
}

// static
Serializer::SerializeResult Serializer::SerializeX509Chain(
    const ct::X509ChainEntry& entry, std::string* result) {
  return SerializeX509Chain(entry.certificate_chain(), result);
}

// static
Serializer::SerializeResult Serializer::SerializeX509Chain(
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
  if (res != OK)
    return res;
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeDigitallySigned(
    const DigitallySigned& sig, string* result) {
  Serializer serializer;
  SerializeResult res = serializer.WriteDigitallySigned(sig);
  if (res != OK)
    return res;
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeV1SignedEntryWithType(
    const ct::LogEntry entry, std::string* result) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      return SerializeV1SignedCertEntryWithType(
          entry.x509_entry().leaf_certificate(), result);
    case ct::PRECERT_ENTRY:
      return SerializeV1SignedPrecertEntryWithType(
          entry.precert_entry().pre_cert().issuer_key_hash(),
          entry.precert_entry().pre_cert().tbs_certificate(), result);
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

void Serializer::WriteFixedBytes(const string& in) {
  output_.append(in);
}

void Serializer::WriteVarBytes(const string& in, size_t max_length) {
  CHECK_LE(in.size(), max_length);

  size_t prefix_length = PrefixLength(max_length);
  WriteUint(in.size(), prefix_length);
  WriteFixedBytes(in);
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
Serializer::SerializeResult Serializer::CheckX509ChainEntryFormat(
    const X509ChainEntry& entry) {
  SerializeResult res = CheckCertificateFormat(entry.leaf_certificate());
  if (res != OK)
    return res;
  return CheckChainFormat(entry.certificate_chain());
}

// static
Serializer::SerializeResult Serializer::CheckPrecertChainEntryFormat(
    const PrecertChainEntry& entry) {
  SerializeResult res = CheckCertificateFormat(entry.pre_certificate());
  if (res != OK)
    return res;
  res = CheckCertificateFormat(entry.pre_cert().tbs_certificate());
  if (res != OK)
    return res;
  res = CheckKeyHashFormat(entry.pre_cert().issuer_key_hash());
  if (res != OK)
    return res;
  return CheckChainFormat(entry.precertificate_chain());
}

Deserializer::Deserializer(const string& input)
    : current_pos_(input.data()), bytes_remaining_(input.size()) {
}

Deserializer::DeserializeResult Deserializer::ReadSCT(
    SignedCertificateTimestamp* sct) {
  int version;
  if (!ReadUint(Serializer::kVersionLengthInBytes, &version))
    return INPUT_TOO_SHORT;
  if (!Version_IsValid(version) || version != ct::V1)
    return UNSUPPORTED_VERSION;
  sct->set_version(ct::V1);
  if (!ReadFixedBytes(Serializer::kKeyIDLengthInBytes,
                      sct->mutable_id()->mutable_key_id()))
    return INPUT_TOO_SHORT;
  // V1 encoding.
  uint64_t timestamp = 0;
  if (!ReadUint(Serializer::kTimestampLengthInBytes, &timestamp))
    return INPUT_TOO_SHORT;
  sct->set_timestamp(timestamp);
  string extensions;
  if (!ReadVarBytes(Serializer::kMaxExtensionsLength, &extensions))
    // In theory, could also be an invalid length prefix, but not if
    // length limits follow byte boundaries.
    return INPUT_TOO_SHORT;
  return ReadDigitallySigned(sct->mutable_signature());
}

// static
Deserializer::DeserializeResult Deserializer::DeserializeSCT(
    const string& in, SignedCertificateTimestamp* sct) {
  Deserializer deserializer(in);
  DeserializeResult res = deserializer.ReadSCT(sct);
  if (res != OK)
    return res;
  if (!deserializer.ReachedEnd())
    return INPUT_TOO_LONG;
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

Deserializer::DeserializeResult Deserializer::ReadMerkleTreeLeaf(
    ct::MerkleTreeLeaf* leaf) {
  int version;
  if (!ReadUint(Serializer::kVersionLengthInBytes, &version))
    return INPUT_TOO_SHORT;
  if (!Version_IsValid(version) || version != ct::V1)
    return UNSUPPORTED_VERSION;
  leaf->set_version(ct::V1);

  int type;
  if (!ReadUint(Serializer::kMerkleLeafTypeLengthInBytes, &type))
    return INPUT_TOO_SHORT;
  if (type != ct::TIMESTAMPED_ENTRY)
    return UNKNOWN_LEAF_TYPE;
  leaf->set_type(ct::TIMESTAMPED_ENTRY);

  ct::TimestampedEntry* entry = leaf->mutable_timestamped_entry();

  uint64_t timestamp;
  if (!ReadUint(Serializer::kTimestampLengthInBytes, &timestamp))
    return INPUT_TOO_SHORT;
  entry->set_timestamp(timestamp);

  int entry_type;
  if (!ReadUint(Serializer::kLogEntryTypeLengthInBytes, &entry_type))
    return INPUT_TOO_SHORT;
  if (entry_type != ct::X509_ENTRY && entry_type != ct::PRECERT_ENTRY)
    return UNKNOWN_LOGENTRY_TYPE;
  entry->set_entry_type(static_cast<ct::LogEntryType>(entry_type));

  if (entry_type == ct::X509_ENTRY) {
    string x509;
    if (!ReadVarBytes(Serializer::kMaxCertificateLength, &x509))
      return INPUT_TOO_SHORT;
    entry->mutable_signed_entry()->set_x509(x509);
  } else {
    string issuer_key_hash;
    if (!ReadFixedBytes(32, &issuer_key_hash))
      return INPUT_TOO_SHORT;
    entry->mutable_signed_entry()->mutable_cert_info()->set_issuer_key_hash(
        issuer_key_hash);
    string tbs_certificate;
    if (!ReadVarBytes(Serializer::kMaxCertificateLength, &tbs_certificate))
      return INPUT_TOO_SHORT;
    entry->mutable_signed_entry()->mutable_cert_info()->set_tbs_certificate(
        tbs_certificate);
  }

  string extensions;
  if (!ReadVarBytes(Serializer::kMaxExtensionsLength, &extensions))
    return INPUT_TOO_SHORT;
  entry->set_extensions(extensions);

  return OK;
}

Deserializer::DeserializeResult Deserializer::DeserializeMerkleTreeLeaf(
    const std::string& in, ct::MerkleTreeLeaf* leaf) {
  Deserializer des(in);
  DeserializeResult ret = des.ReadMerkleTreeLeaf(leaf);
  if (ret != OK)
    return ret;

  if (!des.ReachedEnd())
    return INPUT_TOO_LONG;

  return OK;
}
