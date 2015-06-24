#include <event2/thread.h>
#include <fstream>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <google/protobuf/text_format.h>
#include <iostream>
#include <openssl/err.h>
#include <sstream>

#include "util/etcd.h"
#include "log/etcd_consistent_store.h"
#include "log/logged_certificate.h"
#include "log/log_signer.h"
#include "log/sqlite_db.h"
#include "log/strict_consistent_store.h"
#include "log/tree_signer.h"
#include "proto/ct.pb.h"
#include "tools/clustertool-inl.h"
#include "util/masterelection.h"
#include "util/read_key.h"
#include "util/status.h"
#include "util/thread_pool.h"

namespace libevent = cert_trans::libevent;

using cert_trans::ConsistentStore;
using cert_trans::EtcdClient;
using cert_trans::EtcdConsistentStore;
using cert_trans::LoggedCertificate;
using cert_trans::MasterElection;
using cert_trans::ReadPrivateKey;
using cert_trans::StrictConsistentStore;
using cert_trans::ThreadPool;
using cert_trans::TreeSigner;
using cert_trans::UrlFetcher;
using ct::ClusterConfig;
using ct::SignedTreeHead;
using google::protobuf::TextFormat;
using libevent::EventPumpThread;
using std::ifstream;
using std::make_shared;
using std::ostringstream;
using std::shared_ptr;
using std::string;
using std::unique_ptr;
using util::Status;

DEFINE_string(cluster_config, "",
              "Path of file containing the cluster config (in ASCII proto "
              "format.)");
DEFINE_string(etcd_host, "", "Hostname of the etcd server");
DEFINE_int32(etcd_port, 0, "Port of the etcd server.");
DEFINE_string(key, "", "PEM-encoded server private key file");


namespace {


const char kDefaultClusterConfig[] =
    "minimum_serving_nodes: 2\n"
    "minimum_serving_fraction: 0.75\n";


void Usage() {
  std::cerr << "Usage:\n"
            << "  clustertool [flags] <command> [command opts]\n"
            << "\n"
            << "Commands:\n"
            << "  initlog     Initialise a new log.\n"
            << "  set_config  Set/Change a cluster's config.\n";
}


unique_ptr<LogSigner> BuildLogSigner() {
  CHECK(!FLAGS_key.empty());
  util::StatusOr<EVP_PKEY*> pkey(ReadPrivateKey(FLAGS_key));
  CHECK_EQ(pkey.status(), util::Status::OK);
  return unique_ptr<LogSigner>(new LogSigner(pkey.ValueOrDie()));
}


unique_ptr<TreeSigner<LoggedCertificate>> BuildTreeSigner(
    Database<LoggedCertificate>* db,
    ConsistentStore<LoggedCertificate>* consistent_store,
    LogSigner* log_signer) {
  return unique_ptr<TreeSigner<LoggedCertificate>>(
      new TreeSigner<LoggedCertificate>(std::chrono::duration<double>(0), db,
                                        unique_ptr<CompactMerkleTree>(
                                            new CompactMerkleTree(
                                                new Sha256Hasher)),
                                        consistent_store, log_signer));
}


unique_ptr<MasterElection> BuildAndJoinMasterElection(
    const string node_id, const shared_ptr<libevent::Base>& base,
    EtcdClient* etcd_client) {
  const string kLockDir("/election");
  MasterElection* election(
      new MasterElection(base, etcd_client, kLockDir, node_id));
  election->StartElection();
  election->WaitToBecomeMaster();
  return unique_ptr<MasterElection>(election);
}


ClusterConfig LoadConfig() {
  ClusterConfig cluster_config;
  string cluster_config_str;
  if (FLAGS_cluster_config.empty()) {
    LOG(WARNING) << "Using default ClusterConfig";
    cluster_config_str = kDefaultClusterConfig;
  } else {
    ifstream ifs(FLAGS_cluster_config);
    if (!ifs) {
      LOG(FATAL) << "Couldn't open " << FLAGS_cluster_config;
    }
    ostringstream conf_stream;
    conf_stream << ifs.rdbuf();
    cluster_config_str = conf_stream.str();
  }
  if (!TextFormat::ParseFromString(cluster_config_str, &cluster_config)) {
    LOG(FATAL) << "Couldn't parse ClusterConfig:\n" << cluster_config_str;
  }
  LOG(INFO) << "Using config:\n" << cluster_config.DebugString();
  return cluster_config;
}


}  // namespace


int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  evhtp_ssl_use_threads();
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();
  evthread_use_pthreads();
  FLAGS_logtostderr = true;

  if (argc == 1) {
    Usage();
    return util::error::INVALID_ARGUMENT;
  }

  CHECK(!FLAGS_etcd_host.empty());
  CHECK_NE(0, FLAGS_etcd_port);

  const shared_ptr<libevent::Base> event_base(make_shared<libevent::Base>());
  std::unique_ptr<libevent::EventPumpThread> pump(
      new libevent::EventPumpThread(event_base));
  ThreadPool pool;
  UrlFetcher fetcher(event_base.get(), &pool);

  EtcdClient etcd_client(&fetcher, FLAGS_etcd_host, FLAGS_etcd_port);

  const string node_id("clustertool");
  unique_ptr<MasterElection> election(
      BuildAndJoinMasterElection(node_id, event_base, &etcd_client));
  ThreadPool internal_pool(4);
  StrictConsistentStore<LoggedCertificate> consistent_store(
      election.get(), new EtcdConsistentStore<LoggedCertificate>(
                          event_base.get(), &internal_pool, &etcd_client,
                          election.get(), "/root", node_id));
  SQLiteDB<LoggedCertificate> db("/tmp/clustertooldb");


  const string command(argv[1]);
  Status status;
  if (command == "initlog") {
    unique_ptr<LogSigner> log_signer(BuildLogSigner());
    unique_ptr<TreeSigner<LoggedCertificate>> tree_signer(
        BuildTreeSigner(&db, &consistent_store, log_signer.get()));
    status = InitLog(LoadConfig(), tree_signer.get(), &consistent_store);
  } else if (command == "set_config") {
    CHECK(!FLAGS_cluster_config.empty());
    status = SetClusterConfig(LoadConfig(), &consistent_store);
  } else {
    Usage();
  }

  LOG(INFO) << status;
  election->StopElection();

  return status.error_code();
}
