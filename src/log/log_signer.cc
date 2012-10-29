#include <glog/logging.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10000000
# error "Need OpenSSL >= 1.0.0"
#endif
#include <stdint.h>

#include "ct.pb.h"
#include "log_signer.h"
#include "serial_hasher.h"
#include "serializer.h"
#include "util.h"

using ct::LogEntry;
using ct::LogEntryType;
using ct::DigitallySigned;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;
using std::string;

LogSigner::LogSigner(EVP_PKEY *pkey)
    : pkey_(pkey) {
  assert(pkey_ != NULL);
  switch (pkey_->type) {
    case EVP_PKEY_EC:
      hash_algo_ = DigitallySigned::SHA256;
      sig_algo_ = DigitallySigned::ECDSA;
      break;
    default:
      LOG(FATAL) << "Unsupported key type";
  }
  key_id_ = LogSigVerifier::ComputeKeyID(pkey_);
}

LogSigner::~LogSigner() {
  EVP_PKEY_free(pkey_);
}

LogSigner::SignResult LogSigner::SignV1CertificateTimestamp(
    uint64_t timestamp, LogEntryType type, const string &leaf_certificate,
    const string &extensions, string *result) const {
  string serialized_input;
  Serializer::SerializeResult res = Serializer::SerializeV1SCTSignatureInput(
      timestamp, type, leaf_certificate, extensions, &serialized_input);

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

void LogSigner::Sign(const string &data, DigitallySigned *result) const {
  result->set_hash_algorithm(hash_algo_);
  result->set_sig_algorithm(sig_algo_);
  result->set_signature(RawSign(data));
}

string LogSigner::RawSign(const string &data) const {
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);
  // NOTE: this syntax for setting the hash function requires OpenSSL >= 1.0.0.
  CHECK_EQ(1, EVP_SignInit(&ctx, EVP_sha256()));
  CHECK_EQ(1, EVP_SignUpdate(&ctx, data.data(), data.size()));
  unsigned int sig_size = EVP_PKEY_size(pkey_);
  unsigned char *sig = new unsigned char[sig_size];

  CHECK_EQ(1, EVP_SignFinal(&ctx, sig, &sig_size, pkey_));

  EVP_MD_CTX_cleanup(&ctx);
  string ret(reinterpret_cast<char*>(sig), sig_size);

  delete[] sig;
  return ret;
}

LogSigVerifier::LogSigVerifier(EVP_PKEY *pkey)
    : pkey_(pkey) {
  assert(pkey_ != NULL);
  switch (pkey_->type) {
    case EVP_PKEY_EC:
      hash_algo_ = DigitallySigned::SHA256;
      sig_algo_ = DigitallySigned::ECDSA;
      break;
    default:
      LOG(FATAL) << "Unsupported key type";
  }
  key_id_ = ComputeKeyID(pkey_);
}

LogSigVerifier::~LogSigVerifier() {
  EVP_PKEY_free(pkey_);
}

// static
string LogSigVerifier::ComputeKeyID(EVP_PKEY *pkey) {
  int buf_len = i2d_PUBKEY(pkey, NULL);
  CHECK_GT(buf_len, 0);
  unsigned char *buf = new unsigned char[buf_len];
  unsigned char *p = buf;
  CHECK_EQ(i2d_PUBKEY(pkey, &p), buf_len);
  string keystring(reinterpret_cast<char*>(buf), buf_len);
  string ret = Sha256Hasher::Sha256Digest(keystring);
  delete[] buf;
  return ret;
}

LogSigVerifier::VerifyResult LogSigVerifier::VerifyV1SCTSignature(
    uint64_t timestamp, LogEntryType type, const string &leaf_cert,
    const string &extensions, const string &serialized_sig) const {
  DigitallySigned signature;
  Deserializer::DeserializeResult result =
      Deserializer::DeserializeDigitallySigned(serialized_sig, &signature);
  if (result != Deserializer::OK)
    return GetDeserializeSignatureError(result);

  string serialized_sct;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeV1SCTSignatureInput(timestamp, type, leaf_cert,
                                               extensions, &serialized_sct);
  if (serialize_result != Serializer::OK)
    return GetSerializeError(serialize_result);
  return Verify(serialized_sct, signature);
}

LogSigVerifier::VerifyResult
LogSigVerifier::VerifySCTSignature(const LogEntry &entry,
                                   const SignedCertificateTimestamp &sct)
    const {
  // Try to catch key mismatches early.
  if (sct.id().has_key_id() && sct.id().key_id() != KeyID())
    return KEY_ID_MISMATCH;

  string serialized_input;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeSCTSignatureInput(sct, entry,
                                             &serialized_input);
  if (serialize_result != Serializer::OK)
    return GetSerializeError(serialize_result);
  return Verify(serialized_input, sct.signature());
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
  return Verify(serialized_sth, signature);
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
  return Verify(serialized_sth, sth.signature());
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

LogSigVerifier::VerifyResult LogSigVerifier::Verify(
    const string &input, const DigitallySigned &signature) const {
  if (signature.hash_algorithm() != hash_algo_)
    return HASH_ALGORITHM_MISMATCH;
  if (signature.sig_algorithm() != sig_algo_)
    return SIGNATURE_ALGORITHM_MISMATCH;
  if (!RawVerify(input, signature.signature()))
    return INVALID_SIGNATURE;
  return OK;
}

bool LogSigVerifier::RawVerify(const string &data,
                               const string &sig_string) const {
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);
  // NOTE: this syntax for setting the hash function requires OpenSSL >= 1.0.0.
  CHECK_EQ(1, EVP_VerifyInit(&ctx, EVP_sha256()));
  CHECK_EQ(1, EVP_VerifyUpdate(&ctx, data.data(), data.size()));
  bool ret =
      (EVP_VerifyFinal(
          &ctx, reinterpret_cast<const unsigned char*>(sig_string.data()),
          sig_string.size(), pkey_) == 1);
  EVP_MD_CTX_cleanup(&ctx);
  return ret;
}
