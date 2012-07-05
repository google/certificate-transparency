#include <assert.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10000000
# error "Need OpenSSL >= 1.0.0"
#endif

#include "../include/types.h"
#include "log_signer.h"

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

bstring LogSigner::Sign(const bstring &data) const {
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);
  // NOTE: this syntax for setting the hash function requires OpenSSL >= 1.0.0.
  assert(EVP_SignInit(&ctx, EVP_sha256()) == 1);
  assert(EVP_SignUpdate(&ctx, data.data(), data.size()) == 1);
  unsigned int sig_size = EVP_PKEY_size(pkey_);
  unsigned char *sig = new unsigned char[sig_size];

  assert(EVP_SignFinal(&ctx, sig, &sig_size, pkey_) == 1);

  EVP_MD_CTX_cleanup(&ctx);
  bstring ret(sig, sig_size);

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

bool
LogSigVerifier::Verify(const bstring &data, const bstring &sig_string) const {
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);
  // NOTE: this syntax for setting the hash function requires OpenSSL >= 1.0.0.
  assert(EVP_VerifyInit(&ctx, EVP_sha256()) == 1);
  assert(EVP_VerifyUpdate(&ctx, data.data(), data.size()) == 1);
  bool ret =
      (EVP_VerifyFinal(&ctx, sig_string.data(), sig_string.size(), pkey_) == 1);
  EVP_MD_CTX_cleanup(&ctx);
  return ret;
}
