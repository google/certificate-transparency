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
Serializer::SerializeResult
Serializer::SerializeSCTForSigning(uint64_t timestamp, int type,
                                   const bstring &leaf_certificate,
                                   bstring *result) {
  if (!CertificateEntry_Type_IsValid(type))
    return INVALID_TYPE;
  // Check that the leaf certificate length is within accepted limits.
  SerializeResult res = CheckFormat(leaf_certificate);
  if (res != OK)
    return res;
  Serializer serializer;
  serializer.WriteUint(timestamp, 8);
  serializer.WriteUint(type, 1);
  serializer.WriteVarBytes(leaf_certificate, kMaxCertificateLength);
  result->assign(serializer.SerializedString());
  return OK;
}

Serializer::SerializeResult
Serializer::WriteSCTToken(const SignedCertificateTimestamp &sct) {
  WriteUint(sct.timestamp(), 8);
  return WriteDigitallySigned(sct.signature());
}

// static
Serializer::SerializeResult
Serializer::SerializeSCTToken(const SignedCertificateTimestamp &sct,
                              bstring *result) {
  Serializer serializer;
  SerializeResult res = serializer.WriteSCTToken(sct);
  if (res != OK)
    return res;
  result->assign(serializer.SerializedString());
  return OK;
}

// static
Serializer::SerializeResult
Serializer::SerializeDigitallySigned(const DigitallySigned &sig,
                                     bstring *result) {
  Serializer serializer;
  SerializeResult res = serializer.WriteDigitallySigned(sig);
  if (res != OK)
    return res;
  result->assign(serializer.SerializedString());
  return OK;
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

Serializer::SerializeResult
Serializer::WriteDigitallySigned(const DigitallySigned &sig) {
  SerializeResult res = CheckFormat(sig);
  if (res != OK)
    return res;
  WriteUint(sig.hash_algorithm(), 1);
  WriteUint(sig.sig_algorithm(), 1);
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

Serializer::SerializeResult
Serializer::CheckSignedFormat(const CertificateEntry &entry) {
  return CheckFormat(entry.leaf_certificate());
}

Serializer::SerializeResult
Serializer::CheckFormat(const CertificateEntry &entry) {
  SerializeResult res = CheckFormat(entry.leaf_certificate());
  if (res != OK)
    return res;
  return CheckFormat(entry.intermediates());
}

Serializer::SerializeResult Serializer::CheckFormat(const std::string &cert) {
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

Deserializer::Deserializer(const bstring &input)
    : current_pos_(input.data()),
      bytes_remaining_(input.size()) {}

Deserializer::DeserializeResult
Deserializer::ReadSCTToken(SignedCertificateTimestamp *sct) {
  uint64_t timestamp = 0;
  if (!ReadUint(8, &timestamp))
    return INPUT_TOO_SHORT;
  sct->set_timestamp(timestamp);
  return ReadDigitallySigned(sct->mutable_signature());
}

// static
Deserializer::DeserializeResult
Deserializer::DeserializeSCTToken(const bstring &in,
                                  SignedCertificateTimestamp *sct) {
  Deserializer deserializer(in);
  DeserializeResult res = deserializer.ReadSCTToken(sct);
  if (res != OK)
    return res;
  if (!deserializer.ReachedEnd())
    return INPUT_TOO_LONG;
  return OK;
}

// static
Deserializer::DeserializeResult
Deserializer::DeserializeDigitallySigned(const bstring &in,
                                         DigitallySigned *sig) {
  Deserializer deserializer(in);
  DeserializeResult res = deserializer.ReadDigitallySigned(sig);
  if (res != OK)
    return res;
  if (!deserializer.ReachedEnd())
    return INPUT_TOO_LONG;
  return OK;
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

Deserializer::DeserializeResult
Deserializer::ReadDigitallySigned(DigitallySigned *sig) {
  int hash_algo = -1, sig_algo = -1;
  if (!ReadUint(1, &hash_algo))
    return INPUT_TOO_SHORT;
  if (!DigitallySigned_HashAlgorithm_IsValid(hash_algo))
    return INVALID_HASH_ALGORITHM;
  if (!ReadUint(1, &sig_algo))
    return INPUT_TOO_SHORT;
  if (!DigitallySigned_SignatureAlgorithm_IsValid(sig_algo))
    return INVALID_SIGNATURE_ALGORITHM;

  bstring sig_string;
  if (!ReadVarBytes(Serializer::kMaxSignatureLength, &sig_string))
    return INPUT_TOO_SHORT;
  sig->set_hash_algorithm(
      static_cast<DigitallySigned::HashAlgorithm>(hash_algo));
  sig->set_sig_algorithm(
      static_cast<DigitallySigned::SignatureAlgorithm>(sig_algo));
  sig->set_signature(sig_string);
  return OK;
}
