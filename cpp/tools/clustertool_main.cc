#include <event2/thread.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <openssl/err.h>

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

using cert_trans::ClusterTool;
using cert_trans::EtcdClient;
using cert_trans::EtcdConsistentStore;
using cert_trans::LoggedCertificate;
using cert_trans::MasterElection;
using cert_trans::ReadPrivateKey;
using cert_trans::StrictConsistentStore;
using cert_trans::ThreadPool;
using cert_trans::TreeSigner;
using ct::ClusterConfig;
using ct::SignedTreeHead;
using libevent::EventPumpThread;
using std::make_shared;
using std::shared_ptr;
using std::string;
using util::Status;

DEFINE_string(key, "", "PEM-encoded server private key file");
DEFINE_string(etcd_host, "", "Hostname of the etcd server");
DEFINE_int32(etcd_port, 0, "Port of the etcd server.");


void Usage() {
  std::cerr << "Usage:\n"
            << "  clustertool [flags] <command> [command opts]\n"
            << "\n"
            << "Commands:\n"
            << "  initlog     Initialise a new log.\n";
}


int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  evthread_use_pthreads();

  if (argc == 1) {
    Usage();
    return util::error::INVALID_ARGUMENT;
  }

  CHECK(!FLAGS_key.empty());
  CHECK(!FLAGS_etcd_host.empty());
  CHECK_NE(0, FLAGS_etcd_port);

  util::StatusOr<EVP_PKEY*> pkey(ReadPrivateKey(FLAGS_key));
  CHECK_EQ(pkey.status(), util::Status::OK);
  LogSigner log_signer(pkey.ValueOrDie());

  const shared_ptr<libevent::Base> event_base(make_shared<libevent::Base>());
  std::unique_ptr<libevent::EventPumpThread> pump(
      new libevent::EventPumpThread(event_base));

  EtcdClient etcd_client(event_base, FLAGS_etcd_host, FLAGS_etcd_port);

  const string kLockDir("/election");
  const string node_id("clustertool");
  MasterElection election(event_base, &etcd_client, kLockDir, node_id);
  election.StartElection();
  election.WaitToBecomeMaster();

  ThreadPool internal_pool(4);
  StrictConsistentStore<LoggedCertificate> consistent_store(
      &election,
      new EtcdConsistentStore<LoggedCertificate>(&internal_pool, &etcd_client,
                                                 &election, "/root", node_id));

  SQLiteDB<LoggedCertificate> db("/tmp/loginitdb");
  TreeSigner<LoggedCertificate> tree_signer(std::chrono::duration<double>(0),
                                            &db, &consistent_store,
                                            &log_signer);

  const string command(argv[1]);
  Status status;
  if (command == "initlog") {
    status = ClusterTool<LoggedCertificate>::InitLog(&tree_signer,
                                                     &consistent_store);
  } else {
    Usage();
  }

  LOG(INFO) << status;
  election.StopElection();

  return status.error_code();
}
