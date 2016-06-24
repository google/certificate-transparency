/* -*- indent-tabs-mode: nil -*- */
#include "proto/tls_encoding.h"

#include <math.h>
#include <ostream>
#include <string>

using ct::DigitallySigned;

namespace cert_trans {

namespace serialization {

namespace {

SerializeResult CheckSignatureFormat(const DigitallySigned& sig) {
  // This is just DCHECKED upon setting, so check again.
  if (!DigitallySigned_HashAlgorithm_IsValid(sig.hash_algorithm()))
    return SerializeResult::INVALID_HASH_ALGORITHM;
  if (!DigitallySigned_SignatureAlgorithm_IsValid(sig.sig_algorithm()))
    return SerializeResult::INVALID_SIGNATURE_ALGORITHM;
  if (sig.signature().size() > constants::kMaxSignatureLength)
    return SerializeResult::SIGNATURE_TOO_LONG;
  return SerializeResult::OK;
}

size_t SerializedListLength(const repeated_string& in, size_t max_elem_length,
                            size_t max_total_length) {
  size_t elem_prefix_length = internal::PrefixLength(max_elem_length);
  size_t total_length = 0;

  for (int i = 0; i < in.size(); ++i) {
    if (in.Get(i).size() > max_elem_length ||
        max_total_length - total_length < elem_prefix_length ||
        max_total_length - total_length - elem_prefix_length <
            in.Get(i).size())
      return 0;

    total_length += elem_prefix_length + in.Get(i).size();
  }

  return total_length + internal::PrefixLength(max_total_length);
}

}  // namespace

std::ostream& operator<<(std::ostream& stream, const SerializeResult& r) {
  switch (r) {
    case SerializeResult::OK:
      return stream << "OK";
    case SerializeResult::INVALID_ENTRY_TYPE:
      return stream << "INVALID_ENTRY_TYPE";
    case SerializeResult::EMPTY_CERTIFICATE:
      return stream << "EMPTY_CERTIFICATE";
    case SerializeResult::CERTIFICATE_TOO_LONG:
      return stream << "CERTIFICATE_TOO_LONG";
    case SerializeResult::CERTIFICATE_CHAIN_TOO_LONG:
      return stream << "CERTIFICATE_CHAIN_TOO_LONG";
    case SerializeResult::INVALID_HASH_ALGORITHM:
      return stream << "INVALID_HASH_ALGORITHM";
    case SerializeResult::INVALID_SIGNATURE_ALGORITHM:
      return stream << "INVALID_SIGNATURE_ALGORITHM";
    case SerializeResult::SIGNATURE_TOO_LONG:
      return stream << "SIGNATURE_TOO_LONG";
    case SerializeResult::INVALID_HASH_LENGTH:
      return stream << "INVALID_HASH_LENGTH";
    case SerializeResult::EMPTY_PRECERTIFICATE_CHAIN:
      return stream << "EMPTY_PRECERTIFICATE_CHAIN";
    case SerializeResult::UNSUPPORTED_VERSION:
      return stream << "UNSUPPORTED_VERSION";
    case SerializeResult::EXTENSIONS_TOO_LONG:
      return stream << "EXTENSIONS_TOO_LONG";
    case SerializeResult::INVALID_KEYID_LENGTH:
      return stream << "INVALID_KEYID_LENGTH";
    case SerializeResult::EMPTY_LIST:
      return stream << "EMPTY_LIST";
    case SerializeResult::EMPTY_ELEM_IN_LIST:
      return stream << "EMPTY_ELEM_IN_LIST";
    case SerializeResult::LIST_ELEM_TOO_LONG:
      return stream << "LIST_ELEM_TOO_LONG";
    case SerializeResult::LIST_TOO_LONG:
      return stream << "LIST_TOO_LONG";
    case SerializeResult::EXTENSIONS_NOT_ORDERED:
      return stream << "EXTENSIONS_NOT_ORDERED";
  }
  return stream << "<unknown>";
}

std::ostream& operator<<(std::ostream& stream, const DeserializeResult& r) {
  switch (r) {
    case DeserializeResult::OK:
      return stream << "OK";
    case DeserializeResult::INPUT_TOO_SHORT:
      return stream << "INPUT_TOO_SHORT";
    case DeserializeResult::INVALID_HASH_ALGORITHM:
      return stream << "INVALID_HASH_ALGORITHM";
    case DeserializeResult::INVALID_SIGNATURE_ALGORITHM:
      return stream << "INVALID_SIGNATURE_ALGORITHM";
    case DeserializeResult::INPUT_TOO_LONG:
      return stream << "INPUT_TOO_LONG";
    case DeserializeResult::UNSUPPORTED_VERSION:
      return stream << "UNSUPPORTED_VERSION";
    case DeserializeResult::INVALID_LIST_ENCODING:
      return stream << "INVALID_LIST_ENCODING";
    case DeserializeResult::EMPTY_LIST:
      return stream << "EMPTY_LIST";
    case DeserializeResult::EMPTY_ELEM_IN_LIST:
      return stream << "EMPTY_ELEM_IN_LIST";
    case DeserializeResult::UNKNOWN_LEAF_TYPE:
      return stream << "UNKNOWN_LEAF_TYPE";
    case DeserializeResult::UNKNOWN_LOGENTRY_TYPE:
      return stream << "UNKNOWN_LOGENTRY_TYPE";
    case DeserializeResult::EXTENSIONS_TOO_LONG:
      return stream << "EXTENSIONS_TOO_LONG";
    case DeserializeResult::EXTENSIONS_NOT_ORDERED:
      return stream << "EXTENSIONS_NOT_ORDERED";
  }
  return stream << "<unknown>";
}

void WriteFixedBytes(const std::string& in, std::string* output) {
  output->append(in);
}

void WriteVarBytes(const std::string& in, size_t max_length,
                   std::string* output) {
  CHECK_LE(in.size(), max_length);

  size_t prefix_length = internal::PrefixLength(max_length);
  WriteUint(in.size(), prefix_length, output);
  WriteFixedBytes(in, output);
}

SerializeResult WriteList(const repeated_string& in, size_t max_elem_length,
                          size_t max_total_length, std::string* output) {
  for (int i = 0; i < in.size(); ++i) {
    if (in.Get(i).empty())
      return SerializeResult::EMPTY_ELEM_IN_LIST;
    if (in.Get(i).size() > max_elem_length)
      return SerializeResult::LIST_ELEM_TOO_LONG;
  }
  size_t length = SerializedListLength(in, max_elem_length, max_total_length);
  if (length == 0)
    return SerializeResult::LIST_TOO_LONG;
  size_t prefix_length = internal::PrefixLength(max_total_length);
  CHECK_GE(length, prefix_length);

  WriteUint(length - prefix_length, prefix_length, output);

  for (int i = 0; i < in.size(); ++i)
    WriteVarBytes(in.Get(i), max_elem_length, output);
  return SerializeResult::OK;
}

SerializeResult WriteDigitallySigned(const DigitallySigned& sig,
                                     std::string* output) {
  SerializeResult res = CheckSignatureFormat(sig);
  if (res != SerializeResult::OK)
    return res;
  WriteUint(sig.hash_algorithm(), constants::kHashAlgorithmLengthInBytes,
            output);
  WriteUint(sig.sig_algorithm(), constants::kSigAlgorithmLengthInBytes,
            output);
  WriteVarBytes(sig.signature(), constants::kMaxSignatureLength, output);
  return SerializeResult::OK;
}

namespace internal {

size_t PrefixLength(size_t max_length) {
  CHECK_GT(max_length, 0U);
  return ceil(log2(max_length) / float(8));
}

}  // namespace internal

}  // namespace serialization

}  // namespace cert_trans
