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

// TODO(ekasper): propagate serialization errors all the way up so that
// we know the exact failure reason.
bool LogSigner::SignCertificateTimestamp(uint64_t timestamp,
                                         CertificateEntryType type,
                                         const bstring &leaf_certificate,
                                         bstring *result) const {
  bstring serialized_sct;
  if (!Serializer::SerializeSCTForSigning(timestamp, type, leaf_certificate,
                                          &serialized_sct))
    return false;
  DigitallySigned signature;
  Sign(CERTIFICATE_TIMESTAMP, serialized_sct, &signature);
  Serializer::SerializeDigitallySigned(signature, result);
  return true;
}

bool
LogSigner::SignCertificateTimestamp(SignedCertificateTimestamp *sct) const {
  bstring serialized_sct;
  if(!Serializer::SerializeSCTForSigning(*sct, &serialized_sct))
    return false;
  Sign(CERTIFICATE_TIMESTAMP, serialized_sct, sct->mutable_signature());
  return true;
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

bool LogSigVerifier::VerifySCTSignature(uint64_t timestamp,
                                        LogSigner::CertificateEntryType type,
                                        const bstring &leaf_cert,
                                        const bstring &serialized_sig) const {
  DigitallySigned signature;
  if (!Deserializer::DeserializeDigitallySigned(serialized_sig, &signature))
    return false;
  bstring serialized_sct;
  if (!Serializer::SerializeSCTForSigning(timestamp, type, leaf_cert,
                                          &serialized_sct))
    return false;
  return Verify(LogSigner::CERTIFICATE_TIMESTAMP, serialized_sct, signature);
}

bool LogSigVerifier::VerifySCTSignature(
    const SignedCertificateTimestamp &sct) const {
  bstring serialized_sct;
  if (!Serializer::SerializeSCTForSigning(sct, &serialized_sct))
    return false;
  return Verify(LogSigner::CERTIFICATE_TIMESTAMP, serialized_sct,
                sct.signature());
}

bool LogSigVerifier::Verify(LogSigner::SignatureType type, const bstring &input,
                            const DigitallySigned &signature) const {
  if (signature.hash_algorithm() != hash_algo_ ||
      signature.sig_algorithm() != sig_algo_)
    return false;
  bstring to_be_signed = Serializer::SerializeUint(type, 1);
  to_be_signed.append(input);
  return RawVerify(to_be_signed, signature.signature());
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
