#include <string>

#include "ct.pb.h"
#include "serializer.h"
#include "types.h"

const size_t Serializer::kMaxCertificateLength = (1 << 24) - 1;
const size_t Serializer::kMaxCertificateChainLength = (1 << 24) - 1;
const size_t Serializer::kMaxSignatureLength = (1 << 16) - 1;

// static
size_t Serializer::PrefixLength(size_t max_length) {
  assert(max_length > 0);
  size_t prefix_length = 0;

  for ( ; max_length > 0; max_length >>= 8)
    ++prefix_length;

  return prefix_length;
}

// static
bool Serializer::SerializeForSigning(const SignedCertificateHash &sch,
                                     bstring *result) {
  if (!CheckSignedFormat(sch.entry()))
    return false;
  Serializer serializer;
  serializer.WriteUint(sch.timestamp(), 8);
  serializer.WriteUint(sch.entry().type(), 1);
  serializer.WriteVarBytes(sch.entry().leaf_certificate(),
                           kMaxCertificateLength);
  result->assign(serializer.SerializedString());
  return true;
}

bool Serializer::WriteSCHToken(const SignedCertificateHash &sch) {
  WriteUint(sch.timestamp(), 8);
  if (!WriteDigitallySigned(sch.signature()))
    return false;
  return true;
}

// static
bool Serializer::SerializeSCHToken(const SignedCertificateHash &sch,
                                   bstring *result) {
  Serializer serializer;
  if (!serializer.WriteSCHToken(sch))
    return false;
  result->assign(serializer.SerializedString());
  return true;
}

void Serializer::WriteFixedBytes(const bstring &in) {
  output_.append(in);
}

void Serializer::WriteVarBytes(const bstring &in, size_t max_length) {
  assert(in.size() <= max_length && max_length > 0);

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

bool Serializer::WriteDigitallySigned(const DigitallySigned &sig) {
  if (!CheckFormat(sig))
    return false;
  WriteUint(sig.hash_algorithm(), 1);
  WriteUint(sig.sig_algorithm(), 1);
  WriteVarBytes(sig.signature(), kMaxSignatureLength);
  return true;
}

bool Serializer::CheckFormat(const DigitallySigned &sig) {
  return sig.signature().size() <= kMaxSignatureLength;
}

bool Serializer::CheckSignedFormat(const CertificateEntry &entry) {
  return CheckFormat(entry.leaf_certificate());
}

bool Serializer::CheckFormat(const CertificateEntry &entry) {
  return CheckFormat(entry.leaf_certificate()) &&
      CheckFormat(entry.intermediates());
}

bool Serializer::CheckFormat(const std::string &cert) {
  return !cert.empty() && cert.size() <= kMaxCertificateLength;
}

bool Serializer::CheckFormat(const repeated_string &chain) {
  for (int i = 0; i < chain.size(); ++i) {
    if (!CheckFormat(chain.Get(i)))
      return false;
  }
  return Serializer::CanSerialize(chain, kMaxCertificateLength,
                                  kMaxCertificateChainLength);
}

Deserializer::Deserializer(const bstring &input)
    : current_pos_(input.data()),
      bytes_remaining_(input.size()) {}

bool Deserializer::ReadSCHToken(SignedCertificateHash *sch) {
  uint64_t timestamp = 0;
  if (!ReadUint(8, &timestamp))
    return false;
  sch->set_timestamp(timestamp);
  return ReadDigitallySigned(sch->mutable_signature());
}

// static
bool Deserializer::DeserializeSCHToken(const bstring &in,
                                       SignedCertificateHash *sch) {
  Deserializer deserializer(in);
  return deserializer.ReadSCHToken(sch) && deserializer.ReachedEnd();
}

bool Deserializer::ReadFixedBytes(size_t bytes, bstring *result) {
  if (bytes_remaining_ < bytes)
    return false;
  result->assign(current_pos_, bytes);
  current_pos_ += bytes;
  bytes_remaining_ -= bytes;
  return true;
}

bool Deserializer::ReadVarBytes(size_t max_length, bstring *result) {
  size_t prefix_length = Serializer::PrefixLength(max_length);
  size_t length;
  if (!ReadUint(prefix_length, &length) || length > max_length)
    return false;
  return ReadFixedBytes(length, result);
}

bool Deserializer::ReadDigitallySigned(DigitallySigned *sig) {
  int hash_algo = -1, sig_algo = -1;
  if (!ReadUint(1, &hash_algo) ||
      !DigitallySigned_HashAlgorithm_IsValid(hash_algo))
    return false;
  if (!ReadUint(1, &sig_algo) ||
      !DigitallySigned_SignatureAlgorithm_IsValid(sig_algo))
    return false;

  bstring sig_string;
  if (!ReadVarBytes(Serializer::kMaxSignatureLength, &sig_string))
    return false;
  sig->set_hash_algorithm(
      static_cast<DigitallySigned::HashAlgorithm>(hash_algo));
  sig->set_sig_algorithm(
      static_cast<DigitallySigned::SignatureAlgorithm>(sig_algo));
  sig->set_signature(sig_string);
  return true;
}
