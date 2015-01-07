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
  NO_SUCH_ENGINE,
  ENGINE_CTRL_FAILED,
  ENGINE_INIT_FAILED,
};

KeyError ReadPrivateKey(EVP_PKEY** pkey, const std::string& file);

KeyError LoadEnginePrivateKey(EVP_PKEY** pkey, const std::string& engine_name,
                              const std::string& engine_pre_cmds,
                              const std::string& engine_post_cmds,
                              const std::string& key_id);


}  // namespace util
}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_READ_PRIVATE_KEY_H_
