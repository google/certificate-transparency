#ifndef CERT_TRANS_PROTO_TLS_ENCODING_H_
#define CERT_TRANS_PROTO_TLS_ENCODING_H_

#include <glog/logging.h>
#include <string>

#include "proto/ct.pb.h"

typedef google::protobuf::RepeatedPtrField<std::string> repeated_string;

namespace cert_trans {

namespace serialization {

// Serialization methods return OK on success,
// or the first encountered error on failure.
enum class SerializeResult {
  OK,
  INVALID_ENTRY_TYPE,
  EMPTY_CERTIFICATE,
  // TODO(alcutter): rename these to LEAFDATA_TOO_LONG or similar?
  CERTIFICATE_TOO_LONG,
  CERTIFICATE_CHAIN_TOO_LONG,
  INVALID_HASH_ALGORITHM,
  INVALID_SIGNATURE_ALGORITHM,
  SIGNATURE_TOO_LONG,
  INVALID_HASH_LENGTH,
  EMPTY_PRECERTIFICATE_CHAIN,
  UNSUPPORTED_VERSION,
  EXTENSIONS_TOO_LONG,
  INVALID_KEYID_LENGTH,
  EMPTY_LIST,
  EMPTY_ELEM_IN_LIST,
  LIST_ELEM_TOO_LONG,
  LIST_TOO_LONG,
  EXTENSIONS_NOT_ORDERED,
};

std::ostream& operator<<(std::ostream& stream, const SerializeResult& r);

enum class DeserializeResult {
  OK,
  INPUT_TOO_SHORT,
  INVALID_HASH_ALGORITHM,
  INVALID_SIGNATURE_ALGORITHM,
  INPUT_TOO_LONG,
  UNSUPPORTED_VERSION,
  INVALID_LIST_ENCODING,
  EMPTY_LIST,
  EMPTY_ELEM_IN_LIST,
  UNKNOWN_LEAF_TYPE,
  UNKNOWN_LOGENTRY_TYPE,
  EXTENSIONS_TOO_LONG,
  EXTENSIONS_NOT_ORDERED,
};

std::ostream& operator<<(std::ostream& stream, const DeserializeResult& r);

///////////////////////////////////////////////////////////////////////////////
// Basic serialization functions.                                            //
///////////////////////////////////////////////////////////////////////////////
template <class T>
void WriteUint(T in, size_t bytes, std::string* output) {
  CHECK_LE(bytes, sizeof(in));
  CHECK(bytes == sizeof(in) || in >> (bytes * 8) == 0);
  for (; bytes > 0; --bytes)
    output->push_back(((in & (static_cast<T>(0xff) << ((bytes - 1) * 8))) >>
                       ((bytes - 1) * 8)));
}

// Fixed-length byte array.
void WriteFixedBytes(const std::string& in, std::string* output);

// Variable-length byte array.
// Caller is responsible for checking |in| <= max_length
// TODO(ekasper): could return a bool instead.
void WriteVarBytes(const std::string& in, size_t max_length,
                   std::string* output);

SerializeResult WriteList(const repeated_string& in, size_t max_elem_length,
                          size_t max_total_length, std::string* output);

SerializeResult WriteDigitallySigned(const ct::DigitallySigned& sig,
                                     std::string* output);

namespace constants {
static const size_t kMaxSignatureLength = (1 << 16) - 1;
static const size_t kHashAlgorithmLengthInBytes = 1;
static const size_t kSigAlgorithmLengthInBytes = 1;
}  // namespace constants

namespace internal {

// Returns the number of bytes needed to store a value up to max_length.
size_t PrefixLength(size_t max_length);

}  // namespace internal

}  // namespace serializer

}  // namespace cert_trans

#endif
