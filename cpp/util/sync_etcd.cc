#include "util/sync_etcd.h"

#include <condition_variable>
#include <event2/event.h>
#include <memory>

#include "base/notification.h"
#include "util/libevent_wrapper.h"
#include "util/status.h"

using std::bind;
using std::condition_variable;
using std::pair;
using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;
using std::shared_ptr;
using std::string;
using std::vector;
using util::Status;

namespace cert_trans {

namespace {


struct DoneFunctor1 {
  typedef void result_type;
  template <class P1>
  void operator()(Notification* done, P1* p1_out, const P1& p1_in) const {
    *p1_out = p1_in;
    done->Notify();
  }
};


struct DoneFunctor2 {
  typedef void result_type;
  template <class P1, class P2>
  void operator()(Notification* done, P1* p1_out, P2* p2_out, const P1& p1_in,
                  const P2& p2_in) const {
    *p1_out = p1_in;
    *p2_out = p2_in;
    done->Notify();
  }
};


struct DoneFunctor3 {
  typedef void result_type;
  template <class P1, class P2, class P3>
  void operator()(Notification* done, P1* p1_out, P2* p2_out, P3* p3_out,
                  const P1& p1_in, const P2& p2_in, const P3& p3_in) const {
    *p1_out = p1_in;
    *p2_out = p2_in;
    *p3_out = p3_in;
    done->Notify();
  }
};


template <class F>
Status BlockingCall(const F& async_method) {
  Notification done;
  Status status;
  DoneFunctor1 functor;
  async_method(bind(functor, &done, &status, _1));
  done.WaitForNotification();
  return status;
}


template <class F, class P1>
Status BlockingCall(const F& async_method, P1* p1) {
  Notification done;
  Status status;
  DoneFunctor2 functor;
  async_method(bind(functor, &done, &status, p1, _1, _2));
  done.WaitForNotification();
  return status;
}


template <class F, class P1, class P2>
Status BlockingCall(const F& async_method, P1* p1, P2* p2) {
  Notification done;
  Status status;
  DoneFunctor3 functor;
  async_method(bind(functor, &done, &status, p1, p2, _1, _2, _3));
  done.WaitForNotification();
  return status;
}


}  // namespace


SyncEtcdClient::SyncEtcdClient(EtcdClient* client) : client_(client) {
}


Status SyncEtcdClient::Get(const string& key, EtcdClient::Node* node) const {
  return BlockingCall(bind(&EtcdClient::Get, client_, key, _1), node);
}


Status SyncEtcdClient::GetAll(const string& dir,
                              vector<EtcdClient::Node>* values) const {
  return BlockingCall(bind(&EtcdClient::GetAll, client_, dir, _1), values);
}


Status SyncEtcdClient::Create(const string& key, const string& value,
                              int64_t* index) {
  return BlockingCall(bind(&EtcdClient::Create, client_, key, value, _1),
                      index);
}


util::Status SyncEtcdClient::CreateWithTTL(
    const std::string& key, const std::string& value,
    const std::chrono::duration<int>& ttl, int64_t* index) {
  return BlockingCall(bind(&EtcdClient::CreateWithTTL, client_, key, value,
                           ttl, _1),
                      index);
}


Status SyncEtcdClient::CreateInQueue(const string& dir, const string& value,
                                     string* key, int64_t* index) {
  return BlockingCall(bind(&EtcdClient::CreateInQueue, client_, dir, value,
                           _1),
                      key, index);
}


Status SyncEtcdClient::Update(const string& key, const string& value,
                              const int64_t previous_index,
                              int64_t* new_index) {
  return BlockingCall(bind(&EtcdClient::Update, client_, key, value,
                           previous_index, _1),
                      new_index);
}


Status SyncEtcdClient::UpdateWithTTL(const string& key, const string& value,
                                     const std::chrono::duration<int>& ttl,
                                     const int64_t previous_index,
                                     int64_t* new_index) {
  return BlockingCall(bind(&EtcdClient::UpdateWithTTL, client_, key, value,
                           ttl, previous_index, _1),
                      new_index);
}


Status SyncEtcdClient::ForceSet(const string& key, const string& value,
                                int64_t* new_index) {
  return BlockingCall(bind(&EtcdClient::ForceSet, client_, key, value, _1),
                      new_index);
}


Status SyncEtcdClient::ForceSetWithTTL(const string& key, const string& value,
                                       const std::chrono::duration<int>& ttl,
                                       int64_t* new_index) {
  return BlockingCall(bind(&EtcdClient::ForceSetWithTTL, client_, key, value,
                           ttl, _1),
                      new_index);
}


Status SyncEtcdClient::Delete(const string& key, const int64_t current_index) {
  return BlockingCall(
      bind(&EtcdClient::Delete, client_, key, current_index, _1));
}


}  // namespace cert_trans
