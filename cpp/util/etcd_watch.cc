#include <event2/thread.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <memory>

#include "util/etcd.h"
#include "util/libevent_wrapper.h"
#include "util/sync_task.h"

namespace libevent = cert_trans::libevent;

using cert_trans::EtcdClient;
using cert_trans::UrlFetcher;
using std::cout;
using std::endl;
using std::make_shared;
using std::shared_ptr;
using std::vector;
using util::SyncTask;

DEFINE_string(etcd, "127.0.0.1", "etcd server address");
DEFINE_int32(etcd_port, 4001, "etcd server port");
DEFINE_string(key, "/foo", "path to watch");


void Notify(const vector<EtcdClient::WatchUpdate>& updates) {
  for (const auto& update : updates) {
    if (update.exists_) {
      cout << "key changed: " << update.node_.ToString() << endl;
    } else {
      cout << "key deleted: " << update.node_.ToString() << endl;
    }
  }
}


int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  evthread_use_pthreads();

  const shared_ptr<libevent::Base> event_base(make_shared<libevent::Base>());
  UrlFetcher fetcher(event_base.get());
  EtcdClient etcd(event_base, &fetcher, FLAGS_etcd, FLAGS_etcd_port);

  SyncTask task(event_base.get());
  etcd.Watch(FLAGS_key, Notify, task.task());

  event_base->Dispatch();

  // This shouldn't really happen.
  task.Wait();
  LOG(INFO) << "status: " << task.status();

  return 0;
}
