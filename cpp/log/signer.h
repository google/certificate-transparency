// A base class for signing unstructured data.  This class is mockable.

#ifndef SRC_LOG_SIGNER_H_
#define SRC_LOG_SIGNER_H_

#include <openssl/evp.h>
#include <openssl/x509.h>  // for i2d_PUBKEY
#include <stdint.h>

#include "base/macros.h"
#include "proto/ct.pb.h"

namespace ct {

class Signer {
 public:
  explicit Signer(EVP_PKEY *pkey);
  virtual ~Signer();

  virtual std::string KeyID() const;

  virtual void Sign(const std::string &data, DigitallySigned *signature) const;

 protected:
  // A constructor for mocking.
  Signer();

 private:
  std::string RawSign(const std::string &data) const;

  EVP_PKEY *pkey_;
  DigitallySigned::HashAlgorithm hash_algo_;
  DigitallySigned::SignatureAlgorithm sig_algo_;
  std::string key_id_;

  DISALLOW_COPY_AND_ASSIGN(Signer);
};

}  // namespace ct

#endif  // SRC_LOG_SIGNER_H_
