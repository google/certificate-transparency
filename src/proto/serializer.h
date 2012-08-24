#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <assert.h>
#include <string>

#include "ct.pb.h"
#include "types.h"

// A utility class for writing protocol buffer fields in canonical TLS style.
class Serializer {
 public:
  Serializer() {}
  ~Serializer() {}

  static const size_t kMaxCertificateLength;
  static const size_t kMaxCertificateChainLength;
  static const size_t kMaxSignatureLength;

  static size_t PrefixLength(size_t max_length);

  bstring SerializedString() const { return output_; }

  static bool CheckSignedFormat(const CertificateEntry &entry);

  static bool CheckFormat(const CertificateEntry &entry);

  static bool SerializeForSigning(const SignedCertificateHash &sch,
                                  bstring *result);

  bool WriteSCHToken(const SignedCertificateHash &sch);

  static bool SerializeSCHToken(const SignedCertificateHash &sch,
                                bstring *result);

  template <class T>
  static bstring SerializeUint(T in, size_t bytes) {
    Serializer serializer;
    serializer.WriteUint(in, bytes);
    return serializer.SerializedString();
  }

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

  bool WriteDigitallySigned(const DigitallySigned &sig);

  static bool CheckFormat(const DigitallySigned &sig);

  static bool CheckFormat(const std::string &cert);

  static bool CheckFormat(const repeated_string &chain);

  bstring output_;
};

class Deserializer {
 public:
  // We do not make a copy, so input must remain valid.
  Deserializer(const bstring &input);
  ~Deserializer() {}

  bool ReachedEnd() const { return bytes_remaining_ == 0; }

  bool ReadSCHToken(SignedCertificateHash *sch);

  static bool DeserializeSCHToken(const bstring &in,
                                  SignedCertificateHash *sch);

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

  bool ReadDigitallySigned(DigitallySigned *sig);

  const byte *current_pos_;
  size_t bytes_remaining_;
};
#endif
