/* -*- indent-tabs-mode: nil -*- */
#include "log/log_signer.h"

#include <glog/logging.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <stdint.h>

#include "merkletree/serial_hasher.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"
#include "util/util.h"

using cert_trans::Verifier;
using ct::DigitallySigned;
using ct::LogEntry;
using ct::LogEntryType;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;
using std::string;

#if OPENSSL_VERSION_NUMBER < 0x10000000
# error "Need OpenSSL >= 1.0.0"
#endif

namespace {

LogSigVerifier::VerifyResult ConvertStatus(const Verifier::Status status) {
  switch (status) {
    case Verifier::OK:
      return LogSigVerifier::OK;
    case Verifier::HASH_ALGORITHM_MISMATCH:
      return LogSigVerifier::HASH_ALGORITHM_MISMATCH;
    case Verifier::SIGNATURE_ALGORITHM_MISMATCH:
      return LogSigVerifier::SIGNATURE_ALGORITHM_MISMATCH;
    case Verifier::INVALID_SIGNATURE:
      return LogSigVerifier::INVALID_SIGNATURE;
  }
  LOG(FATAL) << "Unexpected status " << status;
}

}  // namespace

LogSigner::LogSigner(EVP_PKEY *pkey)
    : cert_trans::Signer(pkey) {}

LogSigner::~LogSigner() {}

LogSigner::SignResult LogSigner::SignV1CertificateTimestamp(
    uint64_t timestamp, const string &leaf_certificate,
    const string &extensions, string *result) const {
  string serialized_input;
  Serializer::SerializeResult res =
      Serializer::SerializeV1CertSCTSignatureInput(timestamp, leaf_certificate,
                                                   extensions,
                                                   &serialized_input);

  if (res != Serializer::OK)
    return GetSerializeError(res);

  DigitallySigned signature;
  Sign(serialized_input, &signature);
  CHECK_EQ(Serializer::OK,
           Serializer::SerializeDigitallySigned(signature, result));
  return OK;
}

LogSigner::SignResult LogSigner::SignV1PrecertificateTimestamp(
    uint64_t timestamp, const string &issuer_key_hash,
    const string &tbs_certificate,
    const string &extensions, string *result) const {
  string serialized_input;
  Serializer::SerializeResult res =
      Serializer::SerializeV1PrecertSCTSignatureInput(
          timestamp, issuer_key_hash, tbs_certificate,
          extensions, &serialized_input);

  if (res != Serializer::OK)
    return GetSerializeError(res);

  DigitallySigned signature;
  Sign(serialized_input, &signature);
  CHECK_EQ(Serializer::OK,
           Serializer::SerializeDigitallySigned(signature, result));
  return OK;
}

LogSigner::SignResult
LogSigner::SignCertificateTimestamp(const LogEntry &entry,
                                    SignedCertificateTimestamp *sct) const {
  CHECK(sct->has_timestamp())
      << "Attempt to sign an SCT with a missing timestamp";

  string serialized_input;
  Serializer::SerializeResult res = Serializer::SerializeSCTSignatureInput(
      *sct, entry, &serialized_input);

  if (res != Serializer::OK)
    return GetSerializeError(res);
  Sign(serialized_input, sct->mutable_signature());
  sct->mutable_id()->set_key_id(KeyID());
  return OK;
}

LogSigner::SignResult
LogSigner::SignV1TreeHead(uint64_t timestamp, uint64_t tree_size,
                          const string &root_hash, string *result) const {
  string serialized_sth;
  Serializer::SerializeResult res =
      Serializer::SerializeV1STHSignatureInput(timestamp, tree_size, root_hash,
                                               &serialized_sth);

  if (res != Serializer::OK)
    return GetSerializeError(res);

  DigitallySigned signature;
  Sign(serialized_sth, &signature);
  CHECK_EQ(Serializer::OK,
           Serializer::SerializeDigitallySigned(signature, result));
  return OK;
}

LogSigner::SignResult LogSigner::SignTreeHead(SignedTreeHead *sth) const {
  string serialized_sth;
  Serializer::SerializeResult res =
      Serializer::SerializeSTHSignatureInput(*sth, &serialized_sth);
  if (res != Serializer::OK)
    return GetSerializeError(res);
  Sign(serialized_sth, sth->mutable_signature());
  sth->mutable_id()->set_key_id(KeyID());
  return OK;
}

// static
LogSigner::SignResult
LogSigner::GetSerializeError(Serializer::SerializeResult result) {
  SignResult sign_result;
  switch (result) {
    case Serializer::INVALID_ENTRY_TYPE:
      sign_result = INVALID_ENTRY_TYPE;
      break;
    case Serializer::EMPTY_CERTIFICATE:
      sign_result = EMPTY_CERTIFICATE;
      break;
    case Serializer::CERTIFICATE_TOO_LONG:
      sign_result = CERTIFICATE_TOO_LONG;
      break;
    case Serializer::INVALID_HASH_LENGTH:
      sign_result = INVALID_HASH_LENGTH;
      break;
    case Serializer::UNSUPPORTED_VERSION:
      sign_result = UNSUPPORTED_VERSION;
      break;
    case Serializer::EXTENSIONS_TOO_LONG:
      sign_result = EXTENSIONS_TOO_LONG;
      break;
    default:
      LOG(FATAL) << "Unexpected Serializer error code " << result;
  }
  return sign_result;
}

LogSigVerifier::LogSigVerifier(EVP_PKEY *pkey)
    : Verifier(pkey) {}

LogSigVerifier::~LogSigVerifier() {}

LogSigVerifier::VerifyResult LogSigVerifier::VerifyV1CertSCTSignature(
    uint64_t timestamp, const string &leaf_cert,
    const string &extensions, const string &serialized_sig) const {
  DigitallySigned signature;
  Deserializer::DeserializeResult result =
      Deserializer::DeserializeDigitallySigned(serialized_sig, &signature);
  if (result != Deserializer::OK) {
    LOG(WARNING) << "DeserializeDigitallySigned returned " << result;
    return GetDeserializeSignatureError(result);
  }

  string serialized_sct;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeV1CertSCTSignatureInput(timestamp, leaf_cert,
                                                   extensions, &serialized_sct);
  if (serialize_result != Serializer::OK)
    return GetSerializeError(serialize_result);
  return ConvertStatus(Verify(serialized_sct, signature));
}

LogSigVerifier::VerifyResult LogSigVerifier::VerifyV1PrecertSCTSignature(
    uint64_t timestamp, const string &issuer_key_hash, const string &tbs_cert,
    const string &extensions, const string &serialized_sig) const {
  DigitallySigned signature;
  Deserializer::DeserializeResult result =
      Deserializer::DeserializeDigitallySigned(serialized_sig, &signature);
  if (result != Deserializer::OK)
    return GetDeserializeSignatureError(result);

  string serialized_sct;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeV1PrecertSCTSignatureInput(
          timestamp, issuer_key_hash, tbs_cert, extensions, &serialized_sct);
  if (serialize_result != Serializer::OK)
    return GetSerializeError(serialize_result);
  return ConvertStatus(Verify(serialized_sct, signature));
}


LogSigVerifier::VerifyResult
LogSigVerifier::VerifySCTSignature(const LogEntry &entry,
                                   const SignedCertificateTimestamp &sct)
    const {
  // Try to catch key mismatches early.
  if (sct.id().has_key_id() && sct.id().key_id() != KeyID()) {
    LOG(WARNING) << "Key ID mismatch, got: "
                 << util::HexString(sct.id().key_id()) << " expected: "
                 << util::HexString(KeyID());
    return KEY_ID_MISMATCH;
  }

  string serialized_input;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeSCTSignatureInput(sct, entry,
                                             &serialized_input);
  if (serialize_result != Serializer::OK)
    return GetSerializeError(serialize_result);
  return ConvertStatus(Verify(serialized_input, sct.signature()));
}

LogSigVerifier::VerifyResult LogSigVerifier::VerifyV1STHSignature(
    uint64_t timestamp, uint64_t tree_size, const string &root_hash,
    const string &serialized_sig) const {
  DigitallySigned signature;
  Deserializer::DeserializeResult result =
      Deserializer::DeserializeDigitallySigned(serialized_sig, &signature);
  if (result != Deserializer::OK)
    return GetDeserializeSignatureError(result);

  string serialized_sth;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeV1STHSignatureInput(timestamp, tree_size, root_hash,
                                               &serialized_sth);
  if (serialize_result != Serializer::OK)
    return GetSerializeError(serialize_result);
  return ConvertStatus(Verify(serialized_sth, signature));
}

LogSigVerifier::VerifyResult
LogSigVerifier::VerifySTHSignature(const SignedTreeHead &sth) const {
  if (sth.id().has_key_id() && sth.id().key_id() != KeyID())
    return KEY_ID_MISMATCH;
  string serialized_sth;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeSTHSignatureInput(sth, &serialized_sth);
  if (serialize_result != Serializer::OK)
    return GetSerializeError(serialize_result);
  return ConvertStatus(Verify(serialized_sth, sth.signature()));
}

// static
LogSigVerifier::VerifyResult
LogSigVerifier::GetSerializeError(Serializer::SerializeResult result) {
  VerifyResult verify_result;
  switch (result) {
    case Serializer::INVALID_ENTRY_TYPE:
      verify_result = INVALID_ENTRY_TYPE;
      break;
    case Serializer::EMPTY_CERTIFICATE:
      verify_result = EMPTY_CERTIFICATE;
      break;
    case Serializer::CERTIFICATE_TOO_LONG:
      verify_result = CERTIFICATE_TOO_LONG;
      break;
    case Serializer::INVALID_HASH_LENGTH:
      verify_result = INVALID_HASH_LENGTH;
      break;
    case Serializer::UNSUPPORTED_VERSION:
      verify_result = UNSUPPORTED_VERSION;
      break;
    case Serializer::EXTENSIONS_TOO_LONG:
      verify_result = EXTENSIONS_TOO_LONG;
      break;
    default:
      LOG(FATAL) << "Unexpected Serializer error code " << result;
  }
  return verify_result;
}

// static
LogSigVerifier::VerifyResult
LogSigVerifier::GetDeserializeSignatureError(
    Deserializer::DeserializeResult result) {
  VerifyResult verify_result;
  switch (result) {
    case Deserializer::INPUT_TOO_SHORT:
      verify_result = SIGNATURE_TOO_SHORT;
      break;
    case Deserializer::INVALID_HASH_ALGORITHM:
      verify_result = INVALID_HASH_ALGORITHM;
      break;
    case Deserializer::INVALID_SIGNATURE_ALGORITHM:
      verify_result = INVALID_SIGNATURE_ALGORITHM;
      break;
    case Deserializer::INPUT_TOO_LONG:
      verify_result = SIGNATURE_TOO_LONG;
      break;
    default:
      LOG(FATAL) << "Unexpected Deserializer error code " << result;
  }
  return verify_result;
}
