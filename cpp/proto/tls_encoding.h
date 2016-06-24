#ifndef CERT_TRANS_PROTO_TLS_ENCODING_H_
#define CERT_TRANS_PROTO_TLS_ENCODING_H_

#include <glog/logging.h>
#include <string>

#include "base/macros.h"
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

class TLSDeserializer {
 public:
  // We do not make a copy, so input must remain valid.
  // TODO(pphaneuf): And so we should take a string *, not a string &
  // (which could be to a temporary, and not valid once the
  // constructor returns).
  explicit TLSDeserializer(const std::string& input);

  bool ReadFixedBytes(size_t bytes, std::string* result);

  bool ReadVarBytes(size_t max_length, std::string* result);

  cert_trans::serialization::DeserializeResult ReadList(
      size_t max_total_length, size_t max_elem_length, repeated_string* out);

  cert_trans::serialization::DeserializeResult ReadDigitallySigned(
      ct::DigitallySigned* sig);

  bool ReachedEnd() const {
    return bytes_remaining_ == 0;
  }

  template <class T>
  bool ReadUint(size_t bytes, T* result) {
    if (bytes_remaining_ < bytes)
      return false;
    T res = 0;
    for (size_t i = 0; i < bytes; ++i) {
      res = (res << 8) | static_cast<unsigned char>(*current_pos_);
      ++current_pos_;
    }

    bytes_remaining_ -= bytes;
    *result = res;
    return true;
  }

 private:
  bool ReadLengthPrefix(size_t max_length, size_t* result);
  const char* current_pos_;
  size_t bytes_remaining_;

  DISALLOW_COPY_AND_ASSIGN(TLSDeserializer);
};


#endif
