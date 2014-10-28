#include <event2/thread.h>
#include <functional>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "util/etcd.h"
#include "util/libevent_wrapper.h"

namespace libevent = cert_trans::libevent;

using cert_trans::EtcdClient;
using std::bind;
using std::make_shared;
using std::map;
using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;
using std::shared_ptr;
using std::string;
using std::thread;
using std::unique_ptr;
using std::vector;
using util::Status;

DEFINE_string(etcd, "127.0.0.1", "etcd server address");
DEFINE_int32(etcd_port, 4001, "etcd server port");
DEFINE_int32(requests_per_thread, 10, "number of requests per thread");
DEFINE_int32(bytes_per_request, 10, "number of bytes per requests");
DEFINE_int32(num_threads, 1, "number of threads");

namespace {


void make_request(bool* done, EtcdClient* etcd, int* count,
                  const string& data);


void request_done(bool* done, EtcdClient* etcd, int* count, const string& data,
                  Status status, const string& key, int index) {
  CHECK(status.ok()) << status;
  --*count;
  if (*count > 0)
    make_request(done, etcd, count, data);
  else
    *done = true;
}


void make_request(bool* done, EtcdClient* etcd, int* count,
                  const string& data) {
  etcd->CreateInQueue("/testdir", "value", bind(&request_done, done, etcd,
                                                count, data, _1, _2, _3));
}


void test_etcd() {
  const shared_ptr<libevent::Base> event_base(make_shared<libevent::Base>());
  EtcdClient etcd(event_base, FLAGS_etcd, FLAGS_etcd_port);

  const string data(FLAGS_bytes_per_request, 'x');
  int count(FLAGS_requests_per_thread);
  bool done(false);
  make_request(&done, &etcd, &count, data);

  LOG(INFO) << "calling event_base_dispatch";
  while (!done)
    event_base->DispatchOnce();
  LOG(INFO) << "event_base_dispatch done";
}


}  // namespace


int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  evthread_use_pthreads();

  CHECK_GT(FLAGS_requests_per_thread, 0);
  CHECK_GE(FLAGS_bytes_per_request, 0);
  CHECK_GT(FLAGS_num_threads, 0);

  vector<thread*> threads;
  for (int i = FLAGS_num_threads; i > 0; --i)
    threads.push_back(new thread(&test_etcd));

  for (vector<thread*>::const_iterator it = threads.begin();
       it != threads.end(); ++it) {
    (*it)->join();
    delete *it;
  }

  return 0;
}
