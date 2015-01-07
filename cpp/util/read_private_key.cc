#include "util/read_private_key.h"

#include <openssl/engine.h>
#include <openssl/pem.h>
#include <stdlib.h>
#include <string.h>

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
                              const std::string& engine_pre_cmds,
                              const std::string& engine_post_cmds,
                              const std::string& key_id) {
  ENGINE_load_builtin_engines();
  atexit(ENGINE_cleanup);

  engine = ENGINE_by_id(engine_name.c_str());
  if (!engine)
    return NO_SUCH_ENGINE;
  atexit(EngineFree);

  // Temporary copy of the pre_cmds string that will be modified.
  std::string pre_cmds(engine_pre_cmds);
  const char* cmd = strtok((char*)pre_cmds.c_str(), "\n");
  while (cmd != NULL) {
    char* cmd_arg = (char*)strchr(cmd, ':');
    if (cmd_arg)
      *(cmd_arg++) = '\0';

    if (!ENGINE_ctrl_cmd_string(engine, cmd, cmd_arg, 0))
      return ENGINE_CTRL_FAILED;

    cmd = strtok(NULL, "\n");
  }

  if (!ENGINE_init(engine))
    return ENGINE_INIT_FAILED;
  atexit(EngineFinish);

  // Temporary copy of the post_cmds string that will be modified.
  std::string post_cmds(engine_post_cmds);
  cmd = strtok((char*)post_cmds.c_str(), "\n");
  while (cmd != NULL) {
    char* cmd_arg = (char*)strchr(cmd, ':');
    if (cmd_arg)
      *(cmd_arg++) = '\0';

    if (!ENGINE_ctrl_cmd_string(engine, cmd, cmd_arg, 0))
      return ENGINE_CTRL_FAILED;

    cmd = strtok(NULL, "\n");
  }

  // No password.
  *pkey = ENGINE_load_private_key(engine, key_id.c_str(), 0, 0);
  if (!*pkey)
    return INVALID_KEY;

  return KEY_OK;
}


}  // namespace util
}  // namespace cert_trans
