#include "util/init.h"

#include <event2/thread.h>
#include <evhtp.h>
#include <glog/logging.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string>
#include <unistd.h>

#include "log/ct_extensions.h"
#include "version.h"

using std::string;

namespace util {


void InitCT(int* argc, char** argv[]) {
  google::SetVersionString(cert_trans::kBuildVersion);
  google::ParseCommandLineFlags(argc, argv, true);
  google::InitGoogleLogging(*argv[0]);
  google::InstallFailureSignalHandler();

  evthread_use_pthreads();
  // Set-up OpenSSL for multithreaded use:
  evhtp_ssl_use_threads();

  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();

  cert_trans::LoadCtExtensions();

  LOG(INFO) << "Build version: " << google::VersionString();
}


}  // namespace util
