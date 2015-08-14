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
#include "log/sqlite_db.h"
#include "log/tree_signer.h"
#include "monitoring/gcm/exporter.h"
#include "monitoring/latency.h"
#include "monitoring/monitoring.h"
#include "monitoring/registry.h"
#include "server/json_output.h"
#include "server/proxy.h"
#include "util/etcd.h"
#include "util/periodic_closure.h"
#include "util/read_key.h"
#include "util/status.h"
#include "util/thread_pool.h"
#include "util/uuid.h"

using std::bind;

DEFINE_int32(node_state_refresh_seconds, 10,
             "How often to refresh the ClusterNodeState entry for this node.");
DEFINE_int32(watchdog_seconds, 120,
             "How many seconds without successfully refreshing this node's "
             "before firing the watchdog timer.");
DEFINE_bool(watchdog_timeout_is_fatal, true,
            "Exit if the watchdog timer fires.");

namespace cert_trans {

Gauge<>* latest_local_tree_size_gauge =
    Gauge<>::New("latest_local_tree_size",
                 "Size of latest locally generated STH.");


template <class Logged>
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
         ThreadPool* internal_pool, Database<Logged>* db,
         EtcdClient* etcd_client, UrlFetcher* url_fetcher,
         LogSigner* log_signer, CertChecker* cert_checker);
  ~Server();

  bool IsMaster() const;
  MasterElection* election();
  ConsistentStore<Logged>* consistent_store();
  ClusterStateController<Logged>* cluster_state_controller();
  LogLookup<Logged>* log_lookup();

  void Initialise(bool is_mirror);
  void WaitForReplication() const;
  void Run();

 private:
  const Options options_;
  const std::shared_ptr<libevent::Base> event_base_;
  std::unique_ptr<libevent::EventPumpThread> event_pump_;
  libevent::HttpServer http_server_;
  Database<Logged>* const db_;
  CertChecker* const cert_checker_;
  const std::string node_id_;
  UrlFetcher* const url_fetcher_;
  EtcdClient* const etcd_client_;
  MasterElection election_;
  ThreadPool* internal_pool_;
  util::SyncTask server_task_;
  StrictConsistentStore<Logged> consistent_store_;
  const std::unique_ptr<Frontend> frontend_;
  std::unique_ptr<LogLookup<Logged>> log_lookup_;
  std::unique_ptr<ClusterStateController<LoggedCertificate>>
      cluster_controller_;
  std::unique_ptr<ContinuousFetcher> fetcher_;
  ThreadPool http_pool_;
  JsonOutput json_output_;
  std::unique_ptr<Proxy> proxy_;
  std::unique_ptr<HttpHandler> handler_;
  std::unique_ptr<std::thread> node_refresh_thread_;
  std::unique_ptr<GCMExporter> gcm_exporter_;

  DISALLOW_COPY_AND_ASSIGN(Server);
};


namespace {


void RefreshNodeState(ClusterStateController<LoggedCertificate>* controller,
                      util::Task* task) {
  CHECK_NOTNULL(task);
  const std::chrono::steady_clock::duration period(
      (std::chrono::seconds(FLAGS_node_state_refresh_seconds)));
  std::chrono::steady_clock::time_point target_run_time(
      std::chrono::steady_clock::now());

  while (true) {
    if (task->CancelRequested()) {
      task->Return(util::Status::CANCELLED);
      alarm(0);
    }
    // If we haven't managed to refresh our state file in a timely fashion,
    // then send us a SIGALRM:
    alarm(FLAGS_watchdog_seconds);

    controller->RefreshNodeState();

    const std::chrono::steady_clock::time_point now(
        std::chrono::steady_clock::now());
    while (target_run_time <= now) {
      target_run_time += period;
    }
    std::this_thread::sleep_for(target_run_time - now);
  }
}


void WatchdogTimeout(int) {
  if (FLAGS_watchdog_timeout_is_fatal) {
    LOG(FATAL) << "Watchdog timed out, killing process.";
  } else {
    LOG(INFO) << "Watchdog timeout out, ignoring.";
  }
}


template <class Logged>
std::string GetNodeId(Database<Logged>* db) {
  std::string node_id;
  if (db->NodeId(&node_id) != Database<LoggedCertificate>::LOOKUP_OK) {
    node_id = cert_trans::UUID4();
    LOG(INFO) << "Initializing Node DB with UUID: " << node_id;
    db->InitializeNode(node_id);
  } else {
    LOG(INFO) << "Found DB with Node UUID: " << node_id;
  }
  return node_id;
}


}  // namespace


// static
template <class Logged>
void Server<Logged>::StaticInit() {
  CHECK_NE(SIG_ERR, std::signal(SIGALRM, &WatchdogTimeout));
}


template <class Logged>
Server<Logged>::Server(const Options& opts,
                       const std::shared_ptr<libevent::Base>& event_base,
                       ThreadPool* internal_pool, Database<Logged>* db,
                       EtcdClient* etcd_client, UrlFetcher* url_fetcher,
                       LogSigner* log_signer, CertChecker* cert_checker)
    : options_(opts),
      event_base_(event_base),
      event_pump_(new libevent::EventPumpThread(event_base_)),
      http_server_(*event_base_),
      db_(CHECK_NOTNULL(db)),
      cert_checker_(cert_checker),
      node_id_(GetNodeId(db_)),
      url_fetcher_(CHECK_NOTNULL(url_fetcher)),
      etcd_client_(CHECK_NOTNULL(etcd_client)),
      election_(event_base_, etcd_client_, options_.etcd_root + "/election",
                node_id_),
      internal_pool_(CHECK_NOTNULL(internal_pool)),
      server_task_(internal_pool_),
      consistent_store_(&election_,
                        new EtcdConsistentStore<LoggedCertificate>(
                            event_base_.get(), internal_pool_, etcd_client_,
                            &election_, options_.etcd_root, node_id_)),
      frontend_((log_signer && cert_checker)
                    ? new Frontend(new CertSubmissionHandler(cert_checker),
                                   new FrontendSigner(db_, &consistent_store_,
                                                      log_signer))
                    : nullptr),
      http_pool_(options_.num_http_server_threads),
      json_output_(event_base_.get()) {
  CHECK_LT(0, options_.port);
  CHECK_LT(0, options_.num_http_server_threads);

  if (FLAGS_monitoring == kPrometheus) {
    http_server_.AddHandler("/metrics",
                            bind(&cert_trans::ExportPrometheusMetrics,
                                 std::placeholders::_1));
  } else if (FLAGS_monitoring == kGcm) {
    gcm_exporter_.reset(
        new GCMExporter(options_.server, url_fetcher_, internal_pool_));
  } else {
    LOG(FATAL) << "Please set --monitoring to one of the supported values.";
  }

  http_server_.Bind(nullptr, options_.port);
  election_.StartElection();
}

template <class Logged>
Server<Logged>::~Server() {
  server_task_.Cancel();
  node_refresh_thread_->join();
  server_task_.Wait();
}

template <class Logged>
bool Server<Logged>::IsMaster() const {
  return election_.IsMaster();
}

template <class Logged>
MasterElection* Server<Logged>::election() {
  return &election_;
}


template <class Logged>
ConsistentStore<Logged>* Server<Logged>::consistent_store() {
  return &consistent_store_;
}


template <class Logged>
ClusterStateController<Logged>* Server<Logged>::cluster_state_controller() {
  return cluster_controller_.get();
}


template <class Logged>
LogLookup<Logged>* Server<Logged>::log_lookup() {
  return log_lookup_.get();
}


template <class Logged>
void Server<Logged>::WaitForReplication() const {
  // If we're joining an existing cluster, this node needs to get its database
  // up-to-date with the serving_sth before we can do anything, so we'll wait
  // here for that:
  util::StatusOr<ct::SignedTreeHead> serving_sth(
      consistent_store_.GetServingSTH());
  if (serving_sth.ok()) {
    while (db_->TreeSize() < serving_sth.ValueOrDie().tree_size()) {
      LOG(WARNING) << "Waiting for local database to catch up to serving_sth ("
                   << db_->TreeSize() << " of "
                   << serving_sth.ValueOrDie().tree_size() << ")";
      sleep(1);
    }
  }
}


template <class Logged>
void Server<Logged>::Initialise(bool is_mirror) {
  fetcher_.reset(ContinuousFetcher::New(event_base_.get(), internal_pool_, db_,
                                        !is_mirror)
                     .release());

  log_lookup_.reset(new LogLookup<LoggedCertificate>(db_));

  cluster_controller_.reset(new ClusterStateController<LoggedCertificate>(
      internal_pool_, event_base_, url_fetcher_, db_, &consistent_store_,
      &election_, fetcher_.get()));

  // Publish this node's hostname:port info
  cluster_controller_->SetNodeHostPort(options_.server, options_.port);
  {
    ct::SignedTreeHead db_sth;
    if (db_->LatestTreeHead(&db_sth) ==
        Database<LoggedCertificate>::LOOKUP_OK) {
      cluster_controller_->NewTreeHead(db_sth);
    }
  }

  node_refresh_thread_.reset(new std::thread(&RefreshNodeState,
                                             cluster_controller_.get(),
                                             server_task_.task()));

  proxy_.reset(
      new Proxy(event_base_.get(), &json_output_,
                bind(&ClusterStateController<LoggedCertificate>::GetFreshNodes,
                     cluster_controller_.get()),
                url_fetcher_, &http_pool_));
  handler_.reset(new HttpHandler(&json_output_, log_lookup_.get(), db_,
                                 cluster_controller_.get(), cert_checker_,
                                 frontend_.get(), proxy_.get(), &http_pool_,
                                 event_base_.get()));

  handler_->Add(&http_server_);
}


template <class Logged>
void Server<Logged>::Run() {
  // Ding the temporary event pump because we're about to enter the event loop
  event_pump_.reset();
  event_base_->Dispatch();
}


}  // namespace cert_trans
#endif  // CERT_TRANS_SERVER_SERVER_H_
