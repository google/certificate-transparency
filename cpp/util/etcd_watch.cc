#include <event2/thread.h>
#include <functional>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <memory>

#include "util/etcd.h"
#include "util/libevent_wrapper.h"

namespace libevent = cert_trans::libevent;

using cert_trans::EtcdClient;
using std::bind;
using std::cout;
using std::endl;
using std::make_shared;
using std::placeholders::_1;
using std::shared_ptr;
using std::string;

DEFINE_string(etcd, "127.0.0.1", "etcd server address");
DEFINE_int32(etcd_port, 4001, "etcd server port");
DEFINE_string(key, "/foo", "path to watch");


void Notify(const std::vector<EtcdClient::Watcher::Update>& updates) {
  for (const auto& update : updates) {
    if (update.exists_) {
      cout << "key changed: " << update.node_.ToString();
    } else {
      cout << "key deleted: " << update.node_.ToString();
    }
  }
}


int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  evthread_use_pthreads();

  const shared_ptr<libevent::Base> event_base(make_shared<libevent::Base>());
  EtcdClient etcd(event_base, FLAGS_etcd, FLAGS_etcd_port);
  EtcdClient::Watcher watcher(&etcd, FLAGS_key, bind(&Notify, _1));

  event_base->Dispatch();

  return 0;
}
