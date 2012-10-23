#include <glog/logging.h>
#include <string>

#include "ct.h"
#include "ct.pb.h"
#include "serial_hasher.h"
#include "serializer.h"
#include "types.h"

const size_t Serializer::kMaxCertificateLength = (1 << 24) - 1;
const size_t Serializer::kMaxCertificateChainLength = (1 << 24) - 1;
const size_t Serializer::kMaxSignatureLength = (1 << 16) - 1;

const size_t Serializer::kLogEntryTypeLengthInBytes = 2;
const size_t Serializer::kSignatureTypeLengthInBytes = 1;
const size_t Serializer::kHashAlgorithmLengthInBytes = 1;
const size_t Serializer::kSigAlgorithmLengthInBytes = 1;

using ct::LogEntry;
using ct::LogEntryType_IsValid;
using ct::DigitallySigned;
using ct::DigitallySigned_HashAlgorithm_IsValid;
using ct::DigitallySigned_SignatureAlgorithm_IsValid;
using ct::SignedCertificateTimestamp;
using ct::X509ChainEntry;
using ct::PrecertChainEntry;
using std::string;

// static
size_t Serializer::PrefixLength(size_t max_length) {
  CHECK_GT(max_length, 0);
  size_t prefix_length = 0;

  for ( ; max_length > 0; max_length >>= 8)
    ++prefix_length;

  return prefix_length;
}

// static
Serializer::SerializeResult
Serializer::CheckFormat(const LogEntry &entry) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      return CheckFormat(entry.x509_entry());
    case ct::PRECERT_ENTRY:
      return CheckFormat(entry.precert_entry());
    default:
      return INVALID_ENTRY_TYPE;
  }
}

// static
string Serializer::CertificateSha256Hash(const LogEntry &entry) {
  // Compute the SHA-256 hash of the leaf certificate.
  switch (entry.type()) {
    case ct::X509_ENTRY:
      CHECK(entry.x509_entry().has_leaf_certificate())
          << "Cannot calculate hash: missing leaf certificate";
      return Sha256Hasher::Sha256Digest(
          entry.x509_entry().leaf_certificate());
    case ct::PRECERT_ENTRY:
      CHECK(entry.precert_entry().has_tbs_certificate())
          << "Cannot calculate hash: missing tbs certificate";
      return Sha256Hasher::Sha256Digest(
          entry.precert_entry().tbs_certificate());
    default:
      LOG(FATAL) << "Invalid entry type " << entry.type();
  }
}

// static
Serializer::SerializeResult
Serializer::SerializeSCTSignatureInput(
    uint64_t timestamp, ct::LogEntryType type, const string &certificate,
    string *result) {
  if (!LogEntryType_IsValid(type) || type == ct::UNKNOWN_ENTRY_TYPE)
    return INVALID_ENTRY_TYPE;
  // Check that the leaf certificate length is within accepted limits.
  SerializeResult res = CheckFormat(certificate);
  if (res != OK)
    return res;
  Serializer serializer;
  serializer.WriteUint(ct::CERTIFICATE_TIMESTAMP, kSignatureTypeLengthInBytes);
  serializer.WriteUint(timestamp, 8);
  serializer.WriteUint(type, kLogEntryTypeLengthInBytes);
  serializer.WriteVarBytes(certificate, kMaxCertificateLength);
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult Serializer::SerializeSCTSignatureInput(
    uint64_t timestamp, const LogEntry &entry, string *result) {
  switch (entry.type()) {
    case ct::X509_ENTRY:
      return SerializeSCTSignatureInput(timestamp, ct::X509_ENTRY,
                                        entry.x509_entry().leaf_certificate(),
                                        result);
    case ct::PRECERT_ENTRY:
      return SerializeSCTSignatureInput(timestamp, ct::PRECERT_ENTRY,
                                        entry.precert_entry().tbs_certificate(),
                                        result);
    default:
      return INVALID_ENTRY_TYPE;
  }
}

// static
Serializer::SerializeResult
Serializer::SerializeSTHForSigning(uint64_t timestamp, uint64_t tree_size,
                                   const string &root_hash, string *result) {
  if (root_hash.size() != 32)
    return INVALID_HASH_LENGTH;
  Serializer serializer;
  serializer.WriteUint(ct::TREE_HEAD, kSignatureTypeLengthInBytes);
  serializer.WriteUint(timestamp, 8);
  serializer.WriteUint(tree_size, 8);
  serializer.WriteFixedBytes(root_hash);
  result->assign(serializer.SerializedString());
  return OK;
}

Serializer::SerializeResult
Serializer::WriteSCT(const SignedCertificateTimestamp &sct) {
  WriteUint(sct.timestamp(), 8);
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
size_t Serializer::SerializedLength(const repeated_string &in,
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

Serializer::SerializeResult
Serializer::WriteDigitallySigned(const DigitallySigned &sig) {
  SerializeResult res = CheckFormat(sig);
  if (res != OK)
    return res;
  WriteUint(sig.hash_algorithm(), kHashAlgorithmLengthInBytes);
  WriteUint(sig.sig_algorithm(), kSigAlgorithmLengthInBytes);
  WriteVarBytes(sig.signature(), kMaxSignatureLength);
  return OK;
}

Serializer::SerializeResult
Serializer::CheckFormat(const DigitallySigned &sig) {
  // This is just DCHECKED upon setting, so check again.
  if (!DigitallySigned_HashAlgorithm_IsValid(sig.hash_algorithm()))
    return INVALID_HASH_ALGORITHM;
  if (!DigitallySigned_SignatureAlgorithm_IsValid(sig.sig_algorithm()))
    return INVALID_SIGNATURE_ALGORITHM;
  if (sig.signature().size() > kMaxSignatureLength)
    return SIGNATURE_TOO_LONG;
  return OK;
}

Serializer::SerializeResult Serializer::CheckFormat(const string &cert) {
  if (cert.empty())
    return EMPTY_CERTIFICATE;
  if (cert.size() > kMaxCertificateLength)
    return CERTIFICATE_TOO_LONG;
  return OK;
}

Serializer::SerializeResult
Serializer::CheckFormat(const repeated_string &chain) {
  for (int i = 0; i < chain.size(); ++i) {
    SerializeResult res = CheckFormat(chain.Get(i));
    if (res != OK)
      return res;
  }
  if (!Serializer::CanSerialize(chain, kMaxCertificateLength,
                                kMaxCertificateChainLength))
    return CERTIFICATE_CHAIN_TOO_LONG;
  return OK;
}

// static
Serializer::SerializeResult
Serializer::CheckFormat(const X509ChainEntry &entry) {
  SerializeResult res = CheckFormat(entry.leaf_certificate());
  if (res != OK)
    return res;
  return CheckFormat(entry.certificate_chain());
}

// static
Serializer::SerializeResult
Serializer::CheckFormat(const PrecertChainEntry &entry) {
  SerializeResult res = CheckFormat(entry.tbs_certificate());
  if (res != OK)
    return res;
  if (entry.precertificate_chain_size() == 0)
    return EMPTY_PRECERTIFICATE_CHAIN;
  return CheckFormat(entry.precertificate_chain());
}

Deserializer::Deserializer(const string &input)
    : current_pos_(input.data()),
    bytes_remaining_(input.size()) {}

Deserializer::DeserializeResult Deserializer::ReadSCT(
    SignedCertificateTimestamp *sct) {
  uint64_t timestamp = 0;
  if (!ReadUint(8, &timestamp))
    return INPUT_TOO_SHORT;
  sct->set_timestamp(timestamp);
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
