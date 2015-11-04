#ifndef CERT_TRANS_SERVER_SERVER_H_
#define CERT_TRANS_SERVER_SERVER_H_

#include <chrono>
#include <csignal>
#include <cstring>
#include <functional>
#include <gflags/gflags.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <openssl/crypto.h>

#include "config.h"
#include "log/cert_submission_handler.h"
#include "log/ct_extensions.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/frontend.h"
#include "log/frontend_signer.h"
#include "log/leveldb_db.h"
#include "log/log_lookup.h"
#include "log/log_signer.h"
#include "log/log_verifier.h"
#include "log/logged_entry.h"
#include "log/sqlite_db.h"
#include "log/strict_consistent_store.h"
#include "log/tree_signer.h"
#include "monitoring/gcm/exporter.h"
#include "monitoring/latency.h"
#include "monitoring/monitoring.h"
#include "monitoring/registry.h"
#include "server/handler.h"
#include "server/json_output.h"
#include "server/metrics.h"
#include "server/proxy.h"
#include "util/etcd.h"
#include "util/periodic_closure.h"
#include "util/read_key.h"
#include "util/status.h"
#include "util/thread_pool.h"
#include "util/uuid.h"

namespace cert_trans {


// Size of latest locally generated STH.
Gauge<>* latest_local_tree_size_gauge();


class Server {
 public:
  struct Options {
    Options() : port(0), num_http_server_threads(16) {
    }

    std::string server;
    uint16_t port;

    std::string etcd_root;

    int num_http_server_threads;
  };

  static void StaticInit();

  // Doesn't take ownership of anything.
  Server(const Options& opts,
         const std::shared_ptr<libevent::Base>& event_base,
         ThreadPool* internal_pool, ThreadPool* http_pool, Database* db,
         EtcdClient* etcd_client, UrlFetcher* url_fetcher,
         LogSigner* log_signer, const LogVerifier* log_verifier);
  ~Server();

  void RegisterHandler(HttpHandler* handler);

  bool IsMaster() const;
  MasterElection* election();
  ConsistentStore<LoggedEntry>* consistent_store();
  ClusterStateController<LoggedEntry>* cluster_state_controller();
  LogLookup* log_lookup();
  ContinuousFetcher* continuous_fetcher();

  void Initialise(bool is_mirror);
  void WaitForReplication() const;
  void Run();

 private:
  const Options options_;
  const std::shared_ptr<libevent::Base> event_base_;
  std::unique_ptr<libevent::EventPumpThread> event_pump_;
  libevent::HttpServer http_server_;
  Database* const db_;
  const LogVerifier* const log_verifier_;
  const std::string node_id_;
  UrlFetcher* const url_fetcher_;
  EtcdClient* const etcd_client_;
  MasterElection election_;
  ThreadPool* const internal_pool_;
  util::SyncTask server_task_;
  StrictConsistentStore<LoggedEntry> consistent_store_;
  const std::unique_ptr<Frontend> frontend_;
  std::unique_ptr<LogLookup> log_lookup_;
  std::unique_ptr<ClusterStateController<LoggedEntry>> cluster_controller_;
  std::unique_ptr<ContinuousFetcher> fetcher_;
  ThreadPool* const http_pool_;
  std::unique_ptr<Proxy> proxy_;
  std::unique_ptr<std::thread> node_refresh_thread_;
  std::unique_ptr<GCMExporter> gcm_exporter_;

  DISALLOW_COPY_AND_ASSIGN(Server);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_SERVER_SERVER_H_
