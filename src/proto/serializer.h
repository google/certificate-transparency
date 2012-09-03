#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <assert.h>
#include <stdint.h>
#include <string>

#include "ct.pb.h"
#include "types.h"

// A utility class for writing protocol buffer fields in canonical TLS style.
class Serializer {
 public:
  Serializer() {}
  ~Serializer() {}

  // Serialization methods return OK on success,
  // or the first encountered error on failure.
  enum SerializeResult {
    OK,
    INVALID_TYPE,
    EMPTY_CERTIFICATE,
    CERTIFICATE_TOO_LONG,
    CERTIFICATE_CHAIN_TOO_LONG,
    INVALID_HASH_ALGORITHM,
    INVALID_SIGNATURE_ALGORITHM,
    SIGNATURE_TOO_LONG,
  };

  static const size_t kMaxCertificateLength;
  static const size_t kMaxCertificateChainLength;
  static const size_t kMaxSignatureLength;

  static size_t PrefixLength(size_t max_length);

  bstring SerializedString() const { return output_; }

  static SerializeResult CheckSignedFormat(const CertificateEntry &entry);

  static SerializeResult CheckFormat(const CertificateEntry &entry);

  static SerializeResult SerializeSCTForSigning(uint64_t timestamp, int type,
                                                const bstring &leaf_certificate,
                                                bstring *result);

  static SerializeResult
  SerializeSCTForSigning(const SignedCertificateTimestamp &sct,
                         bstring *result) {
    return SerializeSCTForSigning(sct.timestamp(), sct.entry().type(),
                                  sct.entry().leaf_certificate(), result);
  }

  SerializeResult WriteSCTToken(const SignedCertificateTimestamp &sct);

  static SerializeResult
  SerializeSCTToken(const SignedCertificateTimestamp &sct,
                    bstring *result);

  template <class T>
  static bstring SerializeUint(T in, size_t bytes) {
    Serializer serializer;
    serializer.WriteUint(in, bytes);
    return serializer.SerializedString();
  }

  static SerializeResult SerializeDigitallySigned(const DigitallySigned &sig,
                                                  bstring *result);

 private:
  template <class T>
  void WriteUint(T in, size_t bytes) {
    assert(bytes <= sizeof in);
    assert(bytes == sizeof in || in >> (bytes * 8) == 0);
    bstring result;
    for ( ; bytes > 0; --bytes)
      output_.push_back(
          ((in & (0xff << ((bytes - 1) * 8))) >> ((bytes - 1) * 8)));
  }

  // Fixed-length byte array.
  void WriteFixedBytes(const bstring &in);

  // Variable-length byte array.
  void WriteVarBytes(const bstring &in, size_t max_length);

  static bool CanSerialize(const repeated_string &in,
                           size_t max_elem_length,
                           size_t max_total_length) {
    return SerializedLength(in, max_elem_length, max_total_length) > 0;
  }

  static size_t SerializedLength(const repeated_string &in,
                                 size_t max_elem_length,
                                 size_t max_total_length);

  SerializeResult WriteDigitallySigned(const DigitallySigned &sig);

  static SerializeResult CheckFormat(const DigitallySigned &sig);

  static SerializeResult CheckFormat(const std::string &cert);

  static SerializeResult CheckFormat(const repeated_string &chain);

  bstring output_;
};

class Deserializer {
 public:
  // We do not make a copy, so input must remain valid.
  Deserializer(const bstring &input);
  ~Deserializer() {}

  enum DeserializeResult {
    OK,
    INPUT_TOO_SHORT,
    INVALID_HASH_ALGORITHM,
    INVALID_SIGNATURE_ALGORITHM,
    INPUT_TOO_LONG,
  };

  bool ReachedEnd() const { return bytes_remaining_ == 0; }

  DeserializeResult ReadSCTToken(SignedCertificateTimestamp *sct);

  static DeserializeResult DeserializeSCTToken(const bstring &in,
                                  SignedCertificateTimestamp *sct);

  static DeserializeResult DeserializeDigitallySigned(const bstring &in,
                                         DigitallySigned *sig);

 private:
  template<class T>
  bool ReadUint(size_t bytes, T *result) {
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

  bool ReadFixedBytes(size_t bytes, bstring *result);

  bool ReadVarBytes(size_t max_length, bstring *result);

  DeserializeResult ReadDigitallySigned(DigitallySigned *sig);

  const byte *current_pos_;
  size_t bytes_remaining_;
};
#endif
