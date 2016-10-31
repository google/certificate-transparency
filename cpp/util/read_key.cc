#include "util/read_key.h"

#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <memory>

using std::unique_ptr;

namespace cert_trans {

namespace {


void FileCloser(FILE* fp) {
  if (fp) {
    fclose(fp);
  }
}


}  // namespace


static ENGINE* engine = NULL;

static void EngineFree() {
  ENGINE_free(engine);
}

static void EngineFinish() {
  ENGINE_finish(engine);
}

util::StatusOr<EVP_PKEY*> ReadPrivateKey(const std::string& file) {
  unique_ptr<FILE, void (*)(FILE*)> fp(fopen(file.c_str(), "r"), FileCloser);

  if (!fp) {
    return util::Status(util::error::NOT_FOUND, "key file not found: " + file);
  }

  // No password.
  EVP_PKEY* retval(nullptr);
  PEM_read_PrivateKey(fp.get(), &retval, nullptr, nullptr);
  if (!retval)
    return util::Status(util::error::FAILED_PRECONDITION,
                        "invalid key: " + file);

  return retval;
}


util::StatusOr<EVP_PKEY*> ReadPublicKey(const std::string& file) {
  unique_ptr<FILE, void (*)(FILE*)> fp(fopen(file.c_str(), "r"), FileCloser);

  if (!fp) {
    return util::Status(util::error::NOT_FOUND, "key file not found: " + file);
  }

  // No password.
  EVP_PKEY* retval(nullptr);
  PEM_read_PUBKEY(fp.get(), &retval, nullptr, nullptr);
  if (!retval)
    return util::Status(util::error::FAILED_PRECONDITION,
                        "invalid key: " + file);

  return retval;
}


util::StatusOr<EVP_PKEY*> ReadEnginePrivateKey(const std::string& file, const std::string& engine_name) {
  unique_ptr<FILE, void (*)(FILE*)> fp(fopen(file.c_str(), "r"), FileCloser);

  if (!fp)
    return util::Status(util::error::NOT_FOUND, "key file not found: " + file);
  OPENSSL_config(NULL);
  ENGINE_load_dynamic();
  atexit(ENGINE_cleanup);


  engine = ENGINE_by_id(engine_name.c_str());
  if (!engine)
    return util::Status(util::error::NOT_FOUND, "engine not found: " + engine_name);
  atexit(EngineFree);

  if (!ENGINE_init(engine)) {
    static char buf[1024];
    ERR_error_string(ERR_get_error(), buf);
    return util::Status(util::error::ENGINE_INIT_FAILED, "engine init failed: " + std::string(buf));
  }
  atexit(EngineFinish);

  LOG(INFO) << engine_name << " initialized successfully.";

  EVP_PKEY* retval(nullptr);
  retval = ENGINE_load_private_key(engine, file.c_str(), NULL, NULL);
  if (!retval)
    return util::Status(util::error::FAILED_PRECONDITION, "invalid key: " + file);

  return retval;
}

}  // namespace cert_trans
