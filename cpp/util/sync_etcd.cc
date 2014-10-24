#include "util/sync_etcd.h"

#include <boost/bind.hpp>
#include <boost/make_shared.hpp>
#include <event2/event.h>

#include "util/libevent_wrapper.h"
#include "util/status.h"

using boost::bind;
using boost::condition_variable;
using boost::shared_ptr;
using std::list;
using std::pair;
using std::string;
using util::Status;


namespace cert_trans {

namespace {


struct DoneFunctor1 {
  typedef void result_type;
  template <class P1>
  void operator()(bool* done, P1* p1_out, const P1& p1_in) const {
    *p1_out = p1_in;
    *done = true;
  }
};


struct DoneFunctor2 {
  typedef void result_type;
  template <class P1, class P2>
  void operator()(bool* done, P1* p1_out, P2* p2_out, const P1& p1_in,
                  const P2& p2_in) const {
    *p1_out = p1_in;
    *p2_out = p2_in;
    *done = true;
  }
};


struct DoneFunctor3 {
  typedef void result_type;
  template <class P1, class P2, class P3>
  void operator()(bool* done, P1* p1_out, P2* p2_out, P3* p3_out,
                  const P1& p1_in, const P2& p2_in, const P3& p3_in) const {
    *p1_out = p1_in;
    *p2_out = p2_in;
    *p3_out = p3_in;
    *done = true;
  }
};


template <class F>
Status BlockingCall(boost::shared_ptr<libevent::Base> base, F async_method) {
  bool done(false);
  Status status;
  async_method(bind(DoneFunctor1(), &done, &status, _1));
  while (!done) {
    base->DispatchOnce();
  }
  return status;
}


template <class F, class P1>
Status BlockingCall(boost::shared_ptr<libevent::Base> base, F async_method,
                    P1* p1) {
  bool done(false);
  Status status;
  async_method(bind(DoneFunctor2(), &done, &status, p1, _1, _2));
  while (!done) {
    base->DispatchOnce();
  }
  return status;
}


template <class F, class P1, class P2>
Status BlockingCall(boost::shared_ptr<libevent::Base> base, F async_method,
                    P1* p1, P2* p2) {
  bool done(false);
  Status status;
  async_method(bind(DoneFunctor3(), &done, &status, p1, p2, _1, _2, _3));
  while (!done) {
    base->DispatchOnce();
  }
  return status;
}


}  // namespace


SyncEtcdClient::SyncEtcdClient(const std::string& host, uint16_t port)
    : base_(boost::make_shared<libevent::Base>()),
      client_(new EtcdClient(base_, host, port)) {
}

SyncEtcdClient::SyncEtcdClient(EtcdClient* client)
    : base_(boost::make_shared<libevent::Base>()),
      client_(client) {
}


Status SyncEtcdClient::Get(const string& key, int* index, string* value) {
  return BlockingCall(base_, bind(&EtcdClient::Get, client_.get(), key, _1),
                      index, value);
}


Status SyncEtcdClient::GetAll(const string& dir,
                              list<pair<string, int> >* values) {
  return BlockingCall(base_, bind(&EtcdClient::GetAll, client_.get(), dir, _1),
                      values);
}


Status SyncEtcdClient::Create(const string& key, const string& value,
                              int* index) {
  return BlockingCall(base_,
                      bind(&EtcdClient::Create, client_.get(), key, value, _1),
                      index);
}


Status SyncEtcdClient::CreateInQueue(const string& dir, const string& value,
                                     string* key, int* index) {
  return BlockingCall(base_, bind(&EtcdClient::CreateInQueue, client_.get(),
                                  dir, value, _1),
                      key, index);
}


Status SyncEtcdClient::Update(const string& key, const string& value,
                              const int previous_index, int* new_index) {
  return BlockingCall(base_, bind(&EtcdClient::Update, client_.get(), key,
                                  value, previous_index, _1),
                      new_index);
}


Status SyncEtcdClient::Delete(const string& key, const int current_index) {
  return BlockingCall(base_, bind(&EtcdClient::Delete, client_.get(), key,
                                  current_index, _1));
}


}  // namespace cert_trans
