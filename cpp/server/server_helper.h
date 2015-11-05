#ifndef CERT_TRANS_SERVER_SERVER_HELPER_H_
#define CERT_TRANS_SERVER_SERVER_HELPER_H_

#include <chrono>
#include <csignal>
#include <cstring>
#include <functional>
#include <gflags/gflags.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <openssl/crypto.h>

#include "base/macros.h"
#include "log/database.h"
#include "log/etcd_consistent_store.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/leveldb_db.h"
#include "log/log_signer.h"
#include "log/log_verifier.h"
#include "log/sqlite_db.h"
#include "log/strict_consistent_store.h"
#include "log/tree_signer.h"
#include "monitoring/gcm/exporter.h"
#include "monitoring/latency.h"
#include "monitoring/monitoring.h"
#include "monitoring/registry.h"
#include "server/metrics.h"
#include "util/fake_etcd.h"
#include "util/etcd.h"
#include "util/task.h"
#include "util/thread_pool.h"
#include "server/server.h"

namespace cert_trans {

// This class includes code common to multiple CT servers. It handles parsing
// flags and creating objects that are used by multiple servers. Anything that
// is specific one type of CT server should not be in this class.
//
// Do not link this class into servers that don't use it as it will confuse
// the user with extra flags.
//
// Note methods named ProvideX create a new instance of X each call.
// This class does not own any resources.

class ServerHelper {
 public:
  // Utility class, not for instantiation
  ServerHelper() = delete;
  ~ServerHelper() = delete;

  // Calling this will CHECK if the flag validators failed to register
  static void EnsureValidatorsRegistered();

  // Create one of the supported database types based on flags settings
  static Database* ProvideDatabase();

 private:
  DISALLOW_COPY_AND_ASSIGN(ServerHelper)
  ;
};
}  // namespace cert_trans

#endif  // CERT_TRANS_SERVER_SERVER_HELPER_H_
