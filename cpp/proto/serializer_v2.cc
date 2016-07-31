/* -*- indent-tabs-mode: nil -*- */
#include "proto/serializer_v2.h"

#include <glog/logging.h>

#include "util/status.h"
#include "util/openssl_util.h"
#include "util/openssl_scoped_types.h"

#if defined(OPENSSL_IS_BORINGSSL)
#include <openssl/asn1.h>
#endif

namespace rfc6962_bis {
using util::StatusOr;
using util::Status;
using cert_trans::ScopedOpenSSLBytes;

namespace {
const char kDerOIDTag = 0x06;
// OpenSSL documentation recommends 80, see the BUGS section in:
// https://www.openssl.org/docs/manmaster/crypto/OBJ_obj2txt.html
const size_t kTextOIDMaxSize = 80;
}

OID::OID() : oid_(nullptr) {
}

OID::OID(ASN1_OBJECT* oid) : oid_(oid) {
  CHECK_NOTNULL(oid_);
}

OID::OID(const OID& other) : oid_(nullptr) {
  if (other.oid_ != nullptr) {
    oid_ = OBJ_dup(other.oid_);
  }
}

OID::~OID() {
  if (oid_ != nullptr) {
    ASN1_OBJECT_free(oid_);
  }
}

util::StatusOr<std::string> OID::ToTagMissingDER() const {
  if(oid_ == nullptr) {
    // Uninitialized.
    return Status(util::error::INVALID_ARGUMENT,
                  std::string("OID not initialized."));
  }
  int encoded_length = i2d_ASN1_OBJECT(oid_, NULL);
  if (encoded_length <= 0) {
    return Status(util::error::INVALID_ARGUMENT,
                  std::string("Failed to encode OID: ") +
                  util::DumpOpenSSLErrorStack());
  }

  ScopedOpenSSLBytes encoded_oid(
      reinterpret_cast<uint8_t*>(OPENSSL_malloc(encoded_length)));
  // i2d_ASN1_OBJECT will change the pointer, so have to use a temporary.
  unsigned char* tmp_ptr = encoded_oid.get();
  encoded_length = i2d_ASN1_OBJECT(oid_, &tmp_ptr);
  if (encoded_length <= 0) {
    return Status(util::error::INVALID_ARGUMENT,
                  std::string("Failed to encode OID: ") +
                  util::DumpOpenSSLErrorStack());
  }

  // If the first byte, the tag, does not indicate an OID, then OpenSSL was not
  // used correctly.
  CHECK_EQ(encoded_oid.get()[0], kDerOIDTag);
  // Skip the tag byte.
  std::string out(reinterpret_cast<char*>(encoded_oid.get() + 1), encoded_length - 1);
  return std::move(out);
}

std::string OID::ToString() const {
  if (oid_ == nullptr) {
    return "";
  }

  char output_buffer[kTextOIDMaxSize];
  int encoded_length = i2t_ASN1_OBJECT(output_buffer, kTextOIDMaxSize, oid_);

  return std::string(output_buffer, encoded_length);
}

// static
util::StatusOr<OID> OID::FromString(const std::string& oid_string) {
  ASN1_OBJECT *oid = OBJ_txt2obj(oid_string.c_str(), 0);
  if (oid == nullptr) {
    return Status(util::error::INVALID_ARGUMENT,
                  std::string("Bad OID: ") + oid_string + " "
                  + util::DumpOpenSSLErrorStack());
  }

  return OID(oid);
}

// static
util::StatusOr<OID> OID::FromTagMissingDER(
    const std::string& missing_tag_oid_der) {
  std::string oid_der = std::string(1, kDerOIDTag) + missing_tag_oid_der;
  const unsigned char* data_ptr =
      reinterpret_cast<const unsigned char*>(oid_der.data());

  ASN1_OBJECT *oid = d2i_ASN1_OBJECT(NULL, &data_ptr, oid_der.size());

  if (oid == nullptr) {
    return Status(util::error::INVALID_ARGUMENT,
                  std::string("Bad DER in OID: ") +
                  util::DumpOpenSSLErrorStack());
  }
  return OID(oid);
}

}  // namespace rfc6962_bis
