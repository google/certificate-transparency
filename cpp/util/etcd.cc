#include "util/etcd.h"

#include <boost/make_shared.hpp>
#include <boost/thread.hpp>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <glog/logging.h>
#include <utility>

#include "util/json_wrapper.h"

namespace libevent = cert_trans::libevent;

using boost::lock_guard;
using boost::make_shared;
using boost::mutex;
using boost::shared_ptr;
using cert_trans::EtcdClient;
using std::map;
using std::pair;
using std::string;

namespace {


shared_ptr<evhttp_uri> UriFromHostPort(const string& host, uint16_t port) {
  const shared_ptr<evhttp_uri> retval(CHECK_NOTNULL(evhttp_uri_new()),
                                      evhttp_uri_free);

  evhttp_uri_set_scheme(retval.get(), "http");
  evhttp_uri_set_host(retval.get(), host.c_str());
  evhttp_uri_set_port(retval.get(), port);

  return retval;
}


class EtcdClientImpl : public EtcdClient {
 public:
  EtcdClientImpl(const shared_ptr<libevent::Base>& event_base,
                 const string& host, uint16_t port)
      : event_base_(event_base), leader_(GetConnection(host, port)) {
    LOG(INFO) << "EtcdClientImpl: " << this;
  }
  ~EtcdClientImpl() {
    LOG(INFO) << "~EtcdClientImpl: " << this;
  }

  virtual void Generic(const string& key, const map<string, string>& params,
                       evhttp_cmd_type verb, const GenericCallback& cb);

 private:
  typedef map<pair<string, uint16_t>, shared_ptr<libevent::HttpConnection> >
      ConnMap;
  struct Request {
    Request(EtcdClientImpl* client, evhttp_cmd_type verb, const string& path,
            const string& params, const GenericCallback& cb)
        : client_(client), verb_(verb), path_(path), params_(params), cb_(cb) {
    }

    void Run(const shared_ptr<libevent::HttpConnection>& conn) {
      libevent::HttpRequest* const req(new libevent::HttpRequest(
          bind(&EtcdClientImpl::RequestDone, client_, _1, this)));

      string uri(path_);
      if (verb_ == EVHTTP_REQ_GET) {
        uri += "?" + params_;
      } else {
        evhttp_add_header(evhttp_request_get_output_headers(req->get()),
                          "Content-Type", "application/x-www-form-urlencoded");
        CHECK_EQ(evbuffer_add(evhttp_request_get_output_buffer(req->get()),
                              params_.data(), params_.size()),
                 0);
      }

      conn->MakeRequest(req, verb_, uri.c_str());
    }

    EtcdClientImpl* const client_;
    const evhttp_cmd_type verb_;
    const string path_;
    const string params_;
    const GenericCallback cb_;
  };

  // If MaybeUpdateLeader returns true, the handling of the response
  // should be aborted, as a new leader was found, and the request has
  // been retried on the new leader.
  bool MaybeUpdateLeader(libevent::HttpRequest* req, Request* etcd_req);
  void RequestDone(libevent::HttpRequest* req, Request* etcd_req);

  shared_ptr<libevent::HttpConnection> GetConnection(const string& host,
                                                     uint16_t port);

  const shared_ptr<libevent::Base> event_base_;

  mutex lock_;
  ConnMap conns_;
  // Last known leader.
  shared_ptr<libevent::HttpConnection> leader_;
};


bool EtcdClientImpl::MaybeUpdateLeader(libevent::HttpRequest* req,
                                       Request* etcd_req) {
  if (evhttp_request_get_response_code(req->get()) != 307) {
    return false;
  }

  const char* const location(CHECK_NOTNULL(
      evhttp_find_header(evhttp_request_get_input_headers(req->get()),
                         "location")));

  // TODO(pphaneuf): We only need a deleter, would use unique_ptr, but
  // we don't have C++11.
  const shared_ptr<evhttp_uri> uri(evhttp_uri_parse(location),
                                   &evhttp_uri_free);
  CHECK(uri);
  LOG(INFO) << "etcd leader: " << evhttp_uri_get_host(uri.get()) << ":"
            << evhttp_uri_get_port(uri.get());

  // Update the last known leader, and retry the request on the new
  // leader.
  shared_ptr<libevent::HttpConnection> conn;
  {
    lock_guard<mutex> lock(lock_);
    conn = leader_ = GetConnection(evhttp_uri_get_host(uri.get()),
                                   evhttp_uri_get_port(uri.get()));
  }
  etcd_req->Run(conn);

  return true;
}


void EtcdClientImpl::RequestDone(libevent::HttpRequest* req,
                                 Request* etcd_req) {
  if (!req) {
    LOG(ERROR) << "an unknown error occurred";
    etcd_req->cb_(0, shared_ptr<JsonObject>());
    delete etcd_req;
    return;
  }

  if (MaybeUpdateLeader(req, etcd_req)) {
    return;
  }

  const int status_code(evhttp_request_get_response_code(req->get()));
  if (status_code != 201) {
    LOG(ERROR) << "unexpected status code: " << status_code;

    for (const evkeyval* headers =
             evhttp_request_get_input_headers(req->get())->tqh_first;
         headers; headers = headers->next.tqe_next) {
      LOG(ERROR) << headers->key << ": " << headers->value;
    }
  }

  etcd_req->cb_(status_code, make_shared<JsonObject>(
                                 evhttp_request_get_input_buffer(req->get())));
  delete etcd_req;
}


shared_ptr<libevent::HttpConnection> EtcdClientImpl::GetConnection(
    const string& host, uint16_t port) {
  const pair<string, uint16_t> host_port(make_pair(host, port));
  const ConnMap::const_iterator it(conns_.find(host_port));
  shared_ptr<libevent::HttpConnection> conn;

  if (it == conns_.end()) {
    conn = make_shared<libevent::HttpConnection>(event_base_,
                                                 UriFromHostPort(host, port)
                                                     .get());
    conns_.insert(make_pair(host_port, conn));
  } else {
    conn = it->second;
  }

  return conn;
}


void EtcdClientImpl::Generic(const string& key,
                             const map<string, string>& params,
                             evhttp_cmd_type verb, const GenericCallback& cb) {
  // TODO(pphaneuf): Check that the key starts with a slash.

  string params_str;
  bool first(true);
  for (map<string, string>::const_iterator it = params.begin();
       it != params.end(); ++it) {
    if (first)
      first = false;
    else
      params_str += "&";

    params_str += evhttp_uriencode(it->first.c_str(), it->first.size(), 0);
    params_str += "=";
    params_str += evhttp_uriencode(it->second.c_str(), it->second.size(), 0);
  }

  Request* const etcd_req(
      new Request(this, verb, "/v2/keys" + key, params_str, cb));
  shared_ptr<libevent::HttpConnection> conn;
  {
    lock_guard<mutex> lock(lock_);
    conn = leader_;
  }
  etcd_req->Run(conn);
}


}  // namespace


EtcdClient* EtcdClient::Create(const shared_ptr<libevent::Base>& event_base,
                               const string& host, uint16_t port) {
  LOG(INFO) << "EtcdClient::Create";
  EtcdClientImpl* const retval(new EtcdClientImpl(event_base, host, port));
  return retval;
}
