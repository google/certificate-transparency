#include <assert.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10000000
# error "Need OpenSSL >= 1.0.0"
#endif
#include <stdint.h>

#include "ct.pb.h"
#include "log_signer.h"
#include "serializer.h"
#include "types.h"
#include "util.h"

LogSigner::LogSigner(EVP_PKEY *pkey)
    : pkey_(pkey) {
  assert(pkey_ != NULL);
  switch(pkey_->type) {
    case EVP_PKEY_EC:
      hash_algo_ = DigitallySigned::SHA256;
      sig_algo_ = DigitallySigned::ECDSA;
      break;
    default:
      assert(false);
  }
}

LogSigner::~LogSigner() {
  EVP_PKEY_free(pkey_);
}

LogSigner::SignResult
LogSigner::SignCertificateTimestamp(uint64_t timestamp,
                                    CertificateEntryType type,
                                    const bstring &leaf_certificate,
                                    bstring *result) const {
  bstring serialized_sct;
  Serializer::SerializeResult res =
      Serializer::SerializeSCTForSigning(timestamp, type, leaf_certificate,
                                         &serialized_sct);

  if (res != Serializer::OK)
    return GetSerializeSCTError(res);

  DigitallySigned signature;
  Sign(CERTIFICATE_TIMESTAMP, serialized_sct, &signature);
  res = Serializer::SerializeDigitallySigned(signature, result);
  assert(res == Serializer::OK);
  return OK;
}

LogSigner::SignResult
LogSigner::SignCertificateTimestamp(SignedCertificateTimestamp *sct) const {
  bstring serialized_sct;
  Serializer::SerializeResult res =
      Serializer::SerializeSCTForSigning(*sct, &serialized_sct);
  if (res != Serializer::OK)
    return GetSerializeSCTError(res);
  Sign(CERTIFICATE_TIMESTAMP, serialized_sct, sct->mutable_signature());
  return OK;
}

// static
LogSigner::SignResult
LogSigner::GetSerializeSCTError(Serializer::SerializeResult result) {
  SignResult sign_result = UNKNOWN_ERROR;
  switch (result) {
    case Serializer::INVALID_TYPE:
      sign_result = INVALID_ENTRY_TYPE;
      break;
    case Serializer::EMPTY_CERTIFICATE:
      sign_result = EMPTY_CERTIFICATE;
      break;
    case Serializer::CERTIFICATE_TOO_LONG:
      sign_result = CERTIFICATE_TOO_LONG;
      break;
    default:
      assert(false);
  }
  return sign_result;
}

void LogSigner::Sign(SignatureType type, const bstring &data,
                     DigitallySigned *result) const {
  bstring to_be_signed = Serializer::SerializeUint(type, 1);
  to_be_signed.append(data);

  result->set_hash_algorithm(hash_algo_);
  result->set_sig_algorithm(sig_algo_);
  result->set_signature(RawSign(to_be_signed));
}

bstring LogSigner::RawSign(const bstring &data) const {
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);
  // NOTE: this syntax for setting the hash function requires OpenSSL >= 1.0.0.
  assert(EVP_SignInit(&ctx, EVP_sha256()) == 1);
  assert(EVP_SignUpdate(&ctx, data.data(), data.size()) == 1);
  unsigned int sig_size = EVP_PKEY_size(pkey_);
  unsigned char *sig = new unsigned char[sig_size];

  assert(EVP_SignFinal(&ctx, sig, &sig_size, pkey_) == 1);

  EVP_MD_CTX_cleanup(&ctx);
  bstring ret(reinterpret_cast<byte*>(sig), sig_size);

  delete[] sig;
  return ret;
}

LogSigVerifier::LogSigVerifier(EVP_PKEY *pkey)
    : pkey_(pkey) {
  assert(pkey_ != NULL);
  switch(pkey_->type) {
    case EVP_PKEY_EC:
      hash_algo_ = DigitallySigned::SHA256;
      sig_algo_ = DigitallySigned::ECDSA;
      break;
    default:
      assert(false);
  }
}

LogSigVerifier::~LogSigVerifier() {
  EVP_PKEY_free(pkey_);
}

LogSigVerifier::VerifyResult
LogSigVerifier::VerifySCTSignature(uint64_t timestamp,
                                   LogSigner::CertificateEntryType type,
                                   const bstring &leaf_cert,
                                   const bstring &serialized_sig) const {
  DigitallySigned signature;
  Deserializer::DeserializeResult result =
      Deserializer::DeserializeDigitallySigned(serialized_sig, &signature);
  if (result != Deserializer::OK)
    return GetDeserializeSignatureError(result);

  bstring serialized_sct;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeSCTForSigning(timestamp, type, leaf_cert,
                                         &serialized_sct);
  if (serialize_result != Serializer::OK)
    return GetSerializeSCTError(serialize_result);
  return Verify(LogSigner::CERTIFICATE_TIMESTAMP, serialized_sct, signature);
}

LogSigVerifier::VerifyResult
LogSigVerifier::VerifySCTSignature(const SignedCertificateTimestamp &sct)
    const {
  bstring serialized_sct;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeSCTForSigning(sct, &serialized_sct);
  if (serialize_result != Serializer::OK)
    return GetSerializeSCTError(serialize_result);
  return Verify(LogSigner::CERTIFICATE_TIMESTAMP, serialized_sct,
                sct.signature());
}

// static
LogSigVerifier::VerifyResult
LogSigVerifier::GetSerializeSCTError(Serializer::SerializeResult result) {
  VerifyResult verify_result = UNKNOWN_ERROR;
  switch (result) {
    case Serializer::INVALID_TYPE:
      verify_result = INVALID_ENTRY_TYPE;
      break;
    case Serializer::EMPTY_CERTIFICATE:
      verify_result = EMPTY_CERTIFICATE;
      break;
    case Serializer::CERTIFICATE_TOO_LONG:
      verify_result = CERTIFICATE_TOO_LONG;
      break;
    default:
      assert(false);
  }
  return verify_result;
}

// static
LogSigVerifier::VerifyResult
LogSigVerifier::GetDeserializeSignatureError(
    Deserializer::DeserializeResult result) {
  VerifyResult verify_result = UNKNOWN_ERROR;
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
      assert(false);
  }
  return verify_result;
}

LogSigVerifier::VerifyResult
LogSigVerifier::Verify(LogSigner::SignatureType type, const bstring &input,
                       const DigitallySigned &signature) const {
  if (signature.hash_algorithm() != hash_algo_)
    return HASH_ALGORITHM_MISMATCH;
  if (signature.sig_algorithm() != sig_algo_)
    return SIGNATURE_ALGORITHM_MISMATCH;
  bstring to_be_signed = Serializer::SerializeUint(type, 1);
  to_be_signed.append(input);
  if (!RawVerify(to_be_signed, signature.signature()))
    return INVALID_SIGNATURE;
  return OK;
}

bool LogSigVerifier::RawVerify(const bstring &data,
                               const bstring &sig_string) const {
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);
  // NOTE: this syntax for setting the hash function requires OpenSSL >= 1.0.0.
  assert(EVP_VerifyInit(&ctx, EVP_sha256()) == 1);
  assert(EVP_VerifyUpdate(&ctx, data.data(), data.size()) == 1);
  bool ret =
      (EVP_VerifyFinal(&ctx,
                       reinterpret_cast<const unsigned char*>(sig_string.data()),
                       sig_string.size(), pkey_) == 1);
  EVP_MD_CTX_cleanup(&ctx);
  return ret;
}
