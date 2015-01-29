/* -*- indent-tabs-mode: nil -*- */

#include <event2/thread.h>
#include <functional>
#include <gflags/gflags.h>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <string>

#include "log/cert_checker.h"
#include "log/cert_submission_handler.h"
#include "log/cluster_state_controller.h"
#include "log/ct_extensions.h"
#include "log/etcd_consistent_store.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/frontend.h"
#include "log/frontend_signer.h"
#include "log/log_lookup.h"
#include "log/log_signer.h"
#include "log/sqlite_db.h"
#include "log/strict_consistent_store.h"
#include "log/tree_signer.h"
#include "server/handler.h"
#include "util/etcd.h"
#include "util/fake_etcd.h"
#include "util/libevent_wrapper.h"
#include "util/masterelection.h"
#include "util/read_key.h"
#include "util/thread_pool.h"
#include "util/uuid.h"

DEFINE_string(server, "localhost", "Server host");
DEFINE_int32(port, 9999, "Server port");
DEFINE_string(key, "", "PEM-encoded server private key file");
DEFINE_string(trusted_cert_file, "",
              "File for trusted CA certificates, in concatenated PEM format");
// TODO(alcutter): Just specify a root dir with a single flag.
DEFINE_string(cert_dir, "", "Storage directory for certificates");
DEFINE_string(tree_dir, "", "Storage directory for trees");
DEFINE_string(meta_dir, "", "Storage directory for meta info");
DEFINE_string(sqlite_db, "", "Database for certificate and tree storage");
// TODO(ekasper): sanity-check these against the directory structure.
DEFINE_int32(cert_storage_depth, 0,
             "Subdirectory depth for certificates; if the directory is not "
             "empty, must match the existing depth.");
DEFINE_int32(tree_storage_depth, 0,
             "Subdirectory depth for tree signatures; if the directory is not "
             "empty, must match the existing depth");
DEFINE_int32(log_stats_frequency_seconds, 3600,
             "Interval for logging summary statistics. Approximate: the "
             "server will log statistics if in the beginning of its select "
             "loop, at least this period has elapsed since the last log time. "
             "Must be greater than 0.");
DEFINE_int32(tree_signing_frequency_seconds, 600,
             "How often should we issue a new signed tree head. Approximate: "
             "the signer process will kick off if in the beginning of the "
             "server select loop, at least this period has elapsed since the "
             "last signing. Set this well below the MMD to ensure we sign in "
             "a timely manner. Must be greater than 0.");
DEFINE_double(guard_window_seconds, 60,
              "Unsequenced entries new than this "
              "number of seconds will not be sequenced.");
DEFINE_string(etcd_host, "", "Hostname of the etcd server");
DEFINE_int32(etcd_port, 0, "Port of the etcd server.");

namespace libevent = cert_trans::libevent;

using cert_trans::CertChecker;
using cert_trans::ClusterStateController;
using cert_trans::EtcdClient;
using cert_trans::EtcdConsistentStore;
using cert_trans::FakeEtcdClient;
using cert_trans::FileStorage;
using cert_trans::HttpHandler;
using cert_trans::LoggedCertificate;
using cert_trans::MasterElection;
using cert_trans::ReadPrivateKey;
using cert_trans::StrictConsistentStore;
using cert_trans::ThreadPool;
using cert_trans::TreeSigner;
using cert_trans::Update;
using ct::ClusterNodeState;
using ct::SignedTreeHead;
using google::RegisterFlagValidator;
using std::bind;
using std::chrono::duration;
using std::chrono::duration_cast;
using std::chrono::seconds;
using std::chrono::steady_clock;
using std::function;
using std::make_shared;
using std::shared_ptr;
using std::string;
using std::thread;

// Basic sanity checks on flag values.
static bool ValidatePort(const char* flagname, int port) {
  if (port <= 0 || port > 65535) {
    std::cout << "Port value " << port << " is invalid. " << std::endl;
    return false;
  }
  return true;
}

static const bool port_dummy =
    RegisterFlagValidator(&FLAGS_port, &ValidatePort);

static bool ValidateRead(const char* flagname, const string& path) {
  if (access(path.c_str(), R_OK) != 0) {
    std::cout << "Cannot access " << flagname << " at " << path << std::endl;
    return false;
  }
  return true;
}

static const bool key_dummy = RegisterFlagValidator(&FLAGS_key, &ValidateRead);

static const bool cert_dummy =
    RegisterFlagValidator(&FLAGS_trusted_cert_file, &ValidateRead);

static bool ValidateWrite(const char* flagname, const string& path) {
  if (path != "" && access(path.c_str(), W_OK) != 0) {
    std::cout << "Cannot modify " << flagname << " at " << path << std::endl;
    return false;
  }
  return true;
}

static const bool cert_dir_dummy =
    RegisterFlagValidator(&FLAGS_cert_dir, &ValidateWrite);

static const bool tree_dir_dummy =
    RegisterFlagValidator(&FLAGS_tree_dir, &ValidateWrite);

static bool ValidateIsNonNegative(const char* flagname, int value) {
  if (value < 0) {
    std::cout << flagname << " must not be negative" << std::endl;
    return false;
  }
  return true;
}

static const bool c_st_dummy =
    RegisterFlagValidator(&FLAGS_cert_storage_depth, &ValidateIsNonNegative);
static const bool t_st_dummy =
    RegisterFlagValidator(&FLAGS_tree_storage_depth, &ValidateIsNonNegative);

static bool ValidateIsPositive(const char* flagname, int value) {
  if (value <= 0) {
    std::cout << flagname << " must be greater than 0" << std::endl;
    return false;
  }
  return true;
}

static const bool stats_dummy =
    RegisterFlagValidator(&FLAGS_log_stats_frequency_seconds,
                          &ValidateIsPositive);

static const bool sign_dummy =
    RegisterFlagValidator(&FLAGS_tree_signing_frequency_seconds,
                          &ValidateIsPositive);

void SignMerkleTree(TreeSigner<LoggedCertificate>* tree_signer,
                    const MasterElection* election) {
  const steady_clock::duration period((seconds(FLAGS_tree_signing_frequency_seconds)));
  steady_clock::time_point target_run_time(steady_clock::now());

  while (true) {
    if (election->IsMaster()) {
      CHECK_EQ(tree_signer->UpdateTree(), TreeSigner<LoggedCertificate>::OK);
    } else {
      VLOG(1) << "Not starting signing run since we're not the master.";
    }

    const steady_clock::time_point now(steady_clock::now());
    while (target_run_time <= now) {
      target_run_time += period;
    }

    std::this_thread::sleep_for(target_run_time - now);
  }
}

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  cert_trans::LoadCtExtensions();

  util::StatusOr<EVP_PKEY*> pkey(ReadPrivateKey(FLAGS_key));
  CHECK_EQ(pkey.status(), util::Status::OK);
  LogSigner log_signer(pkey.ValueOrDie());

  CertChecker checker;
  CHECK(checker.LoadTrustedCertificates(FLAGS_trusted_cert_file))
      << "Could not load CA certs from " << FLAGS_trusted_cert_file;

  if (FLAGS_sqlite_db == "")
    CHECK_NE(FLAGS_cert_dir, FLAGS_tree_dir)
        << "Certificate directory and tree directory must differ";

  if ((FLAGS_cert_dir != "" || FLAGS_tree_dir != "") &&
      FLAGS_sqlite_db != "") {
    std::cerr << "Choose either file or sqlite database, not both"
              << std::endl;
    exit(1);
  }

  Database<LoggedCertificate>* db;

  if (FLAGS_sqlite_db != "")
    db = new SQLiteDB<LoggedCertificate>(FLAGS_sqlite_db);
  else
    db = new FileDB<LoggedCertificate>(
        new FileStorage(FLAGS_cert_dir, FLAGS_cert_storage_depth),
        new FileStorage(FLAGS_tree_dir, FLAGS_tree_storage_depth),
        new FileStorage(FLAGS_meta_dir, 0));

  std::string node_id;
  if (db->NodeId(&node_id) != Database<LoggedCertificate>::LOOKUP_OK) {
    node_id = cert_trans::UUID4();
    LOG(INFO) << "Initializing Node DB with UUID: " << node_id;
    db->InitializeNode(node_id);
  } else {
    LOG(INFO) << "Found DB with Node UUID: " << node_id;
  }

  evthread_use_pthreads();
  const shared_ptr<libevent::Base> event_base(make_shared<libevent::Base>());
  // Temporary event pump for while we're setting things up and haven't yet
  // entered the event loop at the bottom:
  std::unique_ptr<libevent::EventPumpThread> pump(
      new libevent::EventPumpThread(event_base));

  const bool stand_alone_mode(FLAGS_etcd_host.empty());

  LOG(INFO) << "Running in "
            << (stand_alone_mode ? "STAND-ALONE" : "CLUSTERED") << " mode.";

  std::unique_ptr<EtcdClient> etcd_client(
      stand_alone_mode
          ? new FakeEtcdClient(event_base)
          : new EtcdClient(event_base, FLAGS_etcd_host, FLAGS_etcd_port));

  // No real reason to let this be configurable per node; you can really
  // shoot yourself in the foot that way by effectively running multiple
  // distinct elections.
  const string kLockDir("/election");
  MasterElection election(event_base, etcd_client.get(), kLockDir, node_id);

  // For now, run with a dedicated thread pool as the executor for our
  // consistent store to avoid the possibility of DoS through thread starvation
  // via HTTP.
  ThreadPool internal_pool(4);
  StrictConsistentStore<LoggedCertificate> consistent_store(
      &election, new EtcdConsistentStore<LoggedCertificate>(&internal_pool,
                                                            etcd_client.get(),
                                                            "/root", node_id));

  TreeSigner<LoggedCertificate> tree_signer(std::chrono::duration<double>(
                                                FLAGS_guard_window_seconds),
                                            db, &consistent_store,
                                            &log_signer);

  if (stand_alone_mode) {
    // Set up a simple single-node environment.
    //
    // Put a sensible single-node config into FakeEtcd. For a real clustered
    // log
    // we'd expect a ClusterConfig already to be present within etcd as part of
    // the provisioning of the log.
    //
    // TODO(alcutter): Note that we're currently broken wrt to restarting the
    // log server when there's data in the log.  It's a temporary thing though,
    // so fear ye not.
    ct::ClusterConfig config;
    config.set_minimum_serving_nodes(1);
    config.set_minimum_serving_fraction(1);
    LOG(INFO) << "Setting default single-node ClusterConfig:\n"
              << config.DebugString();
    consistent_store.SetClusterConfig(config);

    // Since we're a single node cluster, we'll settle that we're the
    // master here, so that we can populate the initial STH
    // (StrictConsistentStore won't allow us to do so unless we're master.)
    election.StartElection();
    election.WaitToBecomeMaster();

    // Do an initial signing run to get the initial STH, again this is
    // temporary until we re-populate FakeEtcd from the DB:
    CHECK_EQ(tree_signer.UpdateTree(), TreeSigner<LoggedCertificate>::OK);

    // Need to boot-strap the Serving STH too because we consider it an error
    // if it's not set, which in turn causes us to not attempt to become
    // master:
    consistent_store.SetServingSTH(tree_signer.LatestSTH());
  }

  ClusterStateController<LoggedCertificate> cluster_controller(
      &internal_pool, &consistent_store, &election);

  const Database<LoggedCertificate>::NotifySTHCallback notify_sth_callback(
      [&cluster_controller](const SignedTreeHead& sth) {
        cluster_controller.NewTreeHead(sth);
      });
  db->AddNotifySTHCallback(&notify_sth_callback);

  Frontend frontend(new CertSubmissionHandler(&checker),
                    new FrontendSigner(db, &consistent_store, &log_signer));
  LogLookup<LoggedCertificate> log_lookup(db);

  // TODO(pphaneuf): We should be remaining in an "unhealthy state"
  // (either not accepting any requests, or returning some internal
  // server error) until we have an STH to serve. We can sign for now,
  // but we might not be a signer.
  thread signer(&SignMerkleTree, &tree_signer, &election);
  ThreadPool pool;
  HttpHandler handler(&log_lookup, db, &checker, &frontend, &pool);

  libevent::HttpServer server(*event_base);
  handler.Add(&server);
  server.Bind(NULL, FLAGS_port);

  std::cout << "READY" << std::endl;

  // Ding the temporary event pump because we're about to enter the event loop
  pump.reset();
  event_base->Dispatch();

  return 0;
}
