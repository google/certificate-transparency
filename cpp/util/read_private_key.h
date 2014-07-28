#ifndef CERT_TRANS_UTIL_READ_PRIVATE_KEY_H_
#define CERT_TRANS_UTIL_READ_PRIVATE_KEY_H_

#include <openssl/evp.h>
#include <string>

namespace cert_trans {
namespace util {


enum KeyError {
  KEY_OK,
  NO_SUCH_FILE,
  INVALID_KEY,
};

KeyError ReadPrivateKey(EVP_PKEY **pkey, const std::string &file);


}  // namespace util
}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_READ_PRIVATE_KEY_H_
