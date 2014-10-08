#include "util/read_private_key.h"

#include <openssl/pem.h>

namespace cert_trans {
namespace util {


KeyError ReadPrivateKey(EVP_PKEY** pkey, const std::string& file) {
  FILE* fp = fopen(file.c_str(), "r");

  if (!fp)
    return NO_SUCH_FILE;

  // No password.
  PEM_read_PrivateKey(fp, pkey, NULL, NULL);
  KeyError retval(KEY_OK);
  if (!*pkey)
    retval = INVALID_KEY;

  fclose(fp);

  return retval;
}


}  // namespace util
}  // namespace cert_trans
