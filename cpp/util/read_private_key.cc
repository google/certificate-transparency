#include "util/read_private_key.h"

#include <openssl/engine.h>
#include <openssl/pem.h>
#include <stdlib.h>

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


static ENGINE* engine = NULL;

static void EngineFree() {
  ENGINE_free(engine);
}

static void EngineFinish() {
  ENGINE_finish(engine);
}

KeyError LoadEnginePrivateKey(EVP_PKEY** pkey, const std::string& engine_name,
                              const std::string& key_id) {
  ENGINE_load_builtin_engines();
  atexit(ENGINE_cleanup);

  engine = ENGINE_by_id(engine_name.c_str());
  if (!engine)
    return NO_SUCH_ENGINE;
  atexit(EngineFree);

  if (!ENGINE_init(engine))
    return ENGINE_INIT_FAILED;
  atexit(EngineFinish);

  // No password.
  *pkey = ENGINE_load_private_key(engine, key_id.c_str(), 0, 0);
  if (!*pkey)
    return INVALID_KEY;

  return KEY_OK;
}


}  // namespace util
}  // namespace cert_trans
