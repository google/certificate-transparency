#include <event2/thread.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>

#include "util/etcd.h"
#include "util/libevent_wrapper.h"
#include "util/sync_task.h"

namespace libevent = cert_trans::libevent;

using cert_trans::EtcdClient;
using cert_trans::UrlFetcher;
using std::cout;
using std::endl;
using std::vector;
using util::SyncTask;

DEFINE_string(etcd, "127.0.0.1", "etcd server address");
DEFINE_int32(etcd_port, 4001, "etcd server port");
DEFINE_string(key, "/foo", "path to watch");


void Notify(const vector<EtcdClient::Node>& updates) {
  for (const auto& update : updates) {
    if (!update.deleted_) {
      cout << "key changed: " << update.ToString() << endl;
    } else {
      cout << "key deleted: " << update.ToString() << endl;
    }
  }
}


int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  evthread_use_pthreads();

  libevent::Base event_base;
  UrlFetcher fetcher(&event_base);
  EtcdClient etcd(&fetcher, FLAGS_etcd, FLAGS_etcd_port);

  SyncTask task(&event_base);
  etcd.Watch(FLAGS_key, Notify, task.task());

  event_base.Dispatch();

  // This shouldn't really happen.
  task.Wait();
  LOG(INFO) << "status: " << task.status();

  return 0;
}
