#include <glog/logging.h>
#include <string>

#include "ct.pb.h"
#include "serializer.h"
#include "types.h"

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

using ct::LogEntry;
using ct::LogEntryType_IsValid;
using ct::DigitallySigned;
using ct::DigitallySigned_HashAlgorithm_IsValid;
using ct::DigitallySigned_SignatureAlgorithm_IsValid;
using ct::SignedCertificateTimestamp;
using ct::SignedCertificateTimestampList;
using ct::X509ChainEntry;
using ct::PrecertChainEntry;
using ct::Version_IsValid;
using std::string;

// static
size_t Serializer::PrefixLength(size_t max_length) {
  CHECK_GT(max_length, 0U);
  size_t prefix_length = 0;

  for ( ; max_length > 0; max_length >>= 8)
    ++prefix_length;

  return prefix_length;
}

// static
Serializer::SerializeResult
Serializer::CheckLogEntryFormat(const LogEntry &entry) {
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
string Serializer::LeafCertificate(const LogEntry &entry) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      CHECK(entry.x509_entry().has_leaf_certificate())
          << "Missing leaf certificate";
      return entry.x509_entry().leaf_certificate();
    case ct::PRECERT_ENTRY:
      CHECK(entry.precert_entry().has_tbs_certificate())
          << "Missing tbs certificate";
      return entry.precert_entry().tbs_certificate();
    default:
      LOG(FATAL) << "Invalid entry type " << entry.type();
  }
}

// static
Serializer::SerializeResult
Serializer::SerializeV1SCTSignatureInput(
    uint64_t timestamp, ct::LogEntryType type, const string &certificate,
    const string &extensions, string *result) {
  if (!LogEntryType_IsValid(type) || type == ct::UNKNOWN_ENTRY_TYPE)
    return INVALID_ENTRY_TYPE;
  // Check that the leaf certificate length is within accepted limits.
  SerializeResult res = CheckCertificateFormat(certificate);
  if (res != OK)
    return res;
  res = CheckExtensionsFormat(extensions);
  if (res != OK)
    return res;
  Serializer serializer;
  serializer.WriteUint(ct::V1, kVersionLengthInBytes);
  serializer.WriteUint(ct::CERTIFICATE_TIMESTAMP, kSignatureTypeLengthInBytes);
  serializer.WriteUint(timestamp, 8);
  serializer.WriteUint(type, kLogEntryTypeLengthInBytes);
  serializer.WriteVarBytes(certificate, kMaxCertificateLength);
  serializer.WriteVarBytes(extensions, kMaxExtensionsLength);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeSCTSignatureInput(
    const SignedCertificateTimestamp &sct, const LogEntry &entry,
    string *result) {
  if (sct.version() != ct::V1)
    return UNSUPPORTED_VERSION;
  switch (entry.type()) {
    case ct::X509_ENTRY:
      return SerializeV1SCTSignatureInput(
          sct.timestamp(), ct::X509_ENTRY,
          entry.x509_entry().leaf_certificate(),
          sct.extension(), result);
    case ct::PRECERT_ENTRY:
      return SerializeV1SCTSignatureInput(
          sct.timestamp(), ct::PRECERT_ENTRY,
          entry.precert_entry().tbs_certificate(),
          sct.extension(), result);
    default:
      return INVALID_ENTRY_TYPE;
  }
}

// static
Serializer::SerializeResult Serializer::SerializeV1STHSignatureInput(
    uint64_t timestamp, uint64_t tree_size,
    const string &root_hash, string *result) {
  if (root_hash.size() != 32)
    return INVALID_HASH_LENGTH;
  Serializer serializer;
  serializer.WriteUint(ct::V1, kVersionLengthInBytes);
  serializer.WriteUint(ct::TREE_HEAD, kSignatureTypeLengthInBytes);
  serializer.WriteUint(timestamp, 8);
  serializer.WriteUint(tree_size, 8);
  serializer.WriteFixedBytes(root_hash);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeSTHSignatureInput(
    const ct::SignedTreeHead &sth, std::string *result) {
  if (sth.version() != ct::V1)
    return UNSUPPORTED_VERSION;
  return SerializeV1STHSignatureInput(sth.timestamp(), sth.tree_size(),
                                      sth.root_hash(), result);
}


Serializer::SerializeResult
Serializer::WriteSCT(const SignedCertificateTimestamp &sct) {
  if (sct.version() != ct::V1)
    return UNSUPPORTED_VERSION;
  SerializeResult res = CheckExtensionsFormat(sct.extension());
  if (res != OK)
    return res;
  if (sct.id().key_id().size() != kKeyIDLengthInBytes)
    return INVALID_KEYID_LENGTH;
  WriteUint(ct::V1, kVersionLengthInBytes);
  WriteFixedBytes(sct.id().key_id());
  WriteUint(sct.timestamp(), 8);
  WriteVarBytes(sct.extension(), kMaxExtensionsLength);
  return WriteDigitallySigned(sct.signature());
}

// static
Serializer::SerializeResult Serializer::SerializeSCT(
    const SignedCertificateTimestamp &sct, string *result) {
  Serializer serializer;
  SerializeResult res = serializer.WriteSCT(sct);
  if (res != OK)
    return res;
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeSCTList(
    const SignedCertificateTimestampList &sct_list, string *result) {
  if (sct_list.sct_list_size() == 0)
    return EMPTY_SCT_LIST;
  for (int i = 0; i < sct_list.sct_list_size(); ++i) {
    if (sct_list.sct_list(i).empty())
      return EMPTY_SCT_IN_LIST;
  }
  return SerializeList(sct_list.sct_list(), kMaxSerializedSCTLength,
                       kMaxSCTListLength, result);
}

// static
Serializer::SerializeResult
Serializer::SerializeDigitallySigned(const DigitallySigned &sig,
                                     string *result) {
  Serializer serializer;
  SerializeResult res = serializer.WriteDigitallySigned(sig);
  if (res != OK)
    return res;
  result->assign(serializer.SerializedString());
  return OK;
}

void Serializer::WriteFixedBytes(const string &in) {
  output_.append(in);
}

void Serializer::WriteVarBytes(const string &in, size_t max_length) {
  CHECK_LE(in.size(), max_length);

  size_t prefix_length = PrefixLength(max_length);
  WriteUint(in.size(), prefix_length);
  WriteFixedBytes(in);
}

// static
size_t Serializer::SerializedListLength(const repeated_string &in,
                                        size_t max_elem_length,
                                        size_t max_total_length) {
  size_t elem_prefix_length = PrefixLength(max_elem_length);
  size_t total_length = 0;

  for (int i = 0; i < in.size(); ++i) {
    if (in.Get(i).size() > max_elem_length ||
        max_total_length - total_length < elem_prefix_length ||
        max_total_length - total_length - elem_prefix_length < in.Get(i).size())
      return 0;

    total_length += elem_prefix_length + in.Get(i).size();
  }

  return total_length + PrefixLength(max_total_length);
}

// static
Serializer::SerializeResult Serializer::SerializeList(
    const repeated_string&in, size_t max_elem_length, size_t max_total_length,
    string *result) {
  size_t length = SerializedListLength(in, max_elem_length, max_total_length);
  if (length == 0)
    return LIST_TOO_LONG;
  size_t prefix_length = PrefixLength(max_total_length);
  CHECK_GE(length, prefix_length);
  Serializer serializer;
  serializer.WriteUint(length - prefix_length, prefix_length);

  for (int i = 0; i < in.size(); ++i)
    serializer.WriteVarBytes(in.Get(i), max_elem_length);
  result->assign(serializer.SerializedString());
  return OK;
}

Serializer::SerializeResult
Serializer::WriteDigitallySigned(const DigitallySigned &sig) {
  SerializeResult res = CheckSignatureFormat(sig);
  if (res != OK)
    return res;
  WriteUint(sig.hash_algorithm(), kHashAlgorithmLengthInBytes);
  WriteUint(sig.sig_algorithm(), kSigAlgorithmLengthInBytes);
  WriteVarBytes(sig.signature(), kMaxSignatureLength);
  return OK;
}

Serializer::SerializeResult
Serializer::CheckSignatureFormat(const DigitallySigned &sig) {
  // This is just DCHECKED upon setting, so check again.
  if (!DigitallySigned_HashAlgorithm_IsValid(sig.hash_algorithm()))
    return INVALID_HASH_ALGORITHM;
  if (!DigitallySigned_SignatureAlgorithm_IsValid(sig.sig_algorithm()))
    return INVALID_SIGNATURE_ALGORITHM;
  if (sig.signature().size() > kMaxSignatureLength)
    return SIGNATURE_TOO_LONG;
  return OK;
}

Serializer::SerializeResult
Serializer::CheckCertificateFormat(const string &cert) {
  if (cert.empty())
    return EMPTY_CERTIFICATE;
  if (cert.size() > kMaxCertificateLength)
    return CERTIFICATE_TOO_LONG;
  return OK;
}

Serializer::SerializeResult
Serializer::CheckExtensionsFormat(const string &extensions) {
  if (extensions.size() > kMaxExtensionsLength)
    return EXTENSIONS_TOO_LONG;
  return OK;
}

Serializer::SerializeResult
    Serializer::CheckChainFormat(const repeated_string &chain) {
  for (int i = 0; i < chain.size(); ++i) {
    SerializeResult res = CheckCertificateFormat(chain.Get(i));
    if (res != OK)
      return res;
  }
  if (Serializer::SerializedListLength(chain, kMaxCertificateLength,
                                       kMaxCertificateChainLength) == 0)
    return CERTIFICATE_CHAIN_TOO_LONG;
  return OK;
}

// static
Serializer::SerializeResult
Serializer::CheckX509ChainEntryFormat(const X509ChainEntry &entry) {
  SerializeResult res = CheckCertificateFormat(entry.leaf_certificate());
  if (res != OK)
    return res;
  return CheckChainFormat(entry.certificate_chain());
}

// static
Serializer::SerializeResult
Serializer::CheckPrecertChainEntryFormat(const PrecertChainEntry &entry) {
  SerializeResult res = CheckCertificateFormat(entry.tbs_certificate());
  if (res != OK)
    return res;
  if (entry.precertificate_chain_size() == 0)
    return EMPTY_PRECERTIFICATE_CHAIN;
  return CheckChainFormat(entry.precertificate_chain());
}

Deserializer::Deserializer(const string &input)
    : current_pos_(input.data()),
    bytes_remaining_(input.size()) {}

Deserializer::DeserializeResult Deserializer::ReadSCT(
    SignedCertificateTimestamp *sct) {
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
  if (!ReadUint(8, &timestamp))
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
    const string &in, SignedCertificateTimestamp *sct) {
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
    const string &in, SignedCertificateTimestampList *sct_list) {
  sct_list->clear_sct_list();
  DeserializeResult res = DeserializeList(
      in, Serializer::kMaxSCTListLength, Serializer::kMaxSerializedSCTLength,
      sct_list->mutable_sct_list());
  if (res != OK)
    return res;
  if (sct_list->sct_list_size() == 0)
    return EMPTY_SCT_LIST;
  for (int i = 0; i < sct_list->sct_list_size(); ++i) {
    if (sct_list->sct_list(i).size() == 0)
      return EMPTY_SCT_IN_LIST;
  }
  return OK;
}

// static
Deserializer::DeserializeResult Deserializer::DeserializeList(
    const string &in, size_t max_total_length, size_t max_elem_length,
    repeated_string *out) {
  Deserializer deserializer(in);
  string serialized_list;
  if (!deserializer.ReadVarBytes(max_total_length, &serialized_list))
    // TODO(ekasper): could also be a length that's too large, if
    // length limits don't follow byte boundaries.
    return INPUT_TOO_SHORT;
  if (!deserializer.ReachedEnd())
    return INPUT_TOO_LONG;
  Deserializer sct_reader(serialized_list);
  repeated_string local_out;
  while (!sct_reader.ReachedEnd()) {
    string serialized_elem;
    if (!sct_reader.ReadVarBytes(max_elem_length, &serialized_elem))
      return INVALID_LIST_ENCODING;
    string *new_elem = local_out.Add();
    new_elem->assign(serialized_elem);
  }
  out->CopyFrom(local_out);
  return OK;
}

// static
Deserializer::DeserializeResult
Deserializer::DeserializeDigitallySigned(const string &in,
                                         DigitallySigned *sig) {
  Deserializer deserializer(in);
  DeserializeResult res = deserializer.ReadDigitallySigned(sig);
  if (res != OK)
    return res;
  if (!deserializer.ReachedEnd())
    return INPUT_TOO_LONG;
  return OK;
}

bool Deserializer::ReadFixedBytes(size_t bytes, string *result) {
  if (bytes_remaining_ < bytes)
    return false;
  result->assign(current_pos_, bytes);
  current_pos_ += bytes;
  bytes_remaining_ -= bytes;
  return true;
}

bool Deserializer::ReadVarBytes(size_t max_length, string *result) {
  size_t prefix_length = Serializer::PrefixLength(max_length);
  size_t length;
  if (!ReadUint(prefix_length, &length) || length > max_length)
    return false;
  return ReadFixedBytes(length, result);
}

Deserializer::DeserializeResult
Deserializer::ReadDigitallySigned(DigitallySigned *sig) {
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
