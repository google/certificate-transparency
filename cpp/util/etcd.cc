#include "util/etcd.h"

#include <boost/lexical_cast.hpp>
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
using std::list;
using std::make_pair;
using std::map;
using std::pair;
using std::string;

namespace cert_trans {

namespace {

shared_ptr<evhttp_uri> UriFromHostPort(const string& host, uint16_t port) {
  const shared_ptr<evhttp_uri> retval(CHECK_NOTNULL(evhttp_uri_new()),
                                      evhttp_uri_free);

  evhttp_uri_set_scheme(retval.get(), "http");
  evhttp_uri_set_host(retval.get(), host.c_str());
  evhttp_uri_set_port(retval.get(), port);

  return retval;
}

}  // namespace

EtcdClient::EtcdClient(const shared_ptr<libevent::Base>& event_base,
                       const string& host, uint16_t port)
    : event_base_(event_base), leader_(GetConnection(host, port)) {
  LOG(INFO) << "EtcdClient: " << this;
}

EtcdClient::EtcdClient() {}

EtcdClient::~EtcdClient() { LOG(INFO) << "~EtcdClient: " << this; }

bool EtcdClient::MaybeUpdateLeader(libevent::HttpRequest* req,
                                   Request* etcd_req) {
  if (evhttp_request_get_response_code(req->get()) != 307) {
    return false;
  }

  const char* const location(CHECK_NOTNULL(evhttp_find_header(
      evhttp_request_get_input_headers(req->get()), "location")));

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

void EtcdClient::RequestDone(libevent::HttpRequest* req, Request* etcd_req) {
  if (!req) {
    LOG(ERROR) << "an unknown error occurred";
    etcd_req->cb_(Status(0, "unknown error"), shared_ptr<JsonObject>());
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

  shared_ptr<JsonObject> json(
      make_shared<JsonObject>(evhttp_request_get_input_buffer(req->get())));
  etcd_req->cb_(Status(status_code, json), json);
  delete etcd_req;
}

void EtcdClient::GetRequestDone(Status status,
                                const boost::shared_ptr<JsonObject>& json,
                                const GetCallback& cb) const {
  if (status.ok()) {
    const JsonObject node(*json, "node");
    if (!node.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'node'"), 0, "");
      return;
    }
    const JsonInt modifiedIndex(node, "modifiedIndex");
    if (!modifiedIndex.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'modifiedIndex'"), 0, "");
      return;
    }
    const JsonString value(node, "value");
    if (!value.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'value'"), 0, "");
      return;
    }
    cb(status, modifiedIndex.Value(), value.Value());
  } else {
    cb(status, -1, "");
  }
}

void EtcdClient::GetAllRequestDone(Status status,
                                   const boost::shared_ptr<JsonObject>& json,
                                   const GetAllCallback& cb) const {
  if (status.ok()) {
    const JsonObject node(*json, "node");
    if (!node.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'node'"),
         list<pair<string, int> >());
      return;
    }
    const JsonArray value_nodes(node, "nodes");
    if (!value_nodes.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'nodes'"),
         list<pair<string, int> >());
      return;
    }
    list<pair<string, int> > values;
    for (int i = 0; i < value_nodes.Length(); ++i) {
      const JsonObject entry(value_nodes, i);
      if (!entry.Ok()) {
        cb(Status(0, "Invalid JSON: Couldn't get 'value_nodes' index " +
                         boost::lexical_cast<string>(i)),
           list<pair<string, int> >());
        return;
      }
      const JsonString value(entry, "value");
      if (!value.Ok()) {
        cb(Status(0, "Invalid JSON: Couldn't find 'value'"),
           list<pair<string, int> >());
        return;
      }
      const JsonInt modifiedIndex(entry, "modifiedIndex");
      if (!modifiedIndex.Ok()) {
        cb(Status(0, "Invalid JSON: Coulnd't find 'modifiedIndex'"),
           list<pair<string, int> >());
        return;
      }
      values.push_back(make_pair(value.Value(), modifiedIndex.Value()));
    }
    cb(status, values);
  } else {
    cb(status, list<pair<string, int> >());
  }
}

void EtcdClient::CreateRequestDone(Status status,
                                   const boost::shared_ptr<JsonObject>& json,
                                   const CreateCallback& cb) const {
  if (status.ok()) {
    const JsonObject node(*json, "node");
    if (!node.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'node'"), 0);
      return;
    }
    const JsonInt createdIndex(node, "createdIndex");
    if (!createdIndex.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'createdIndex'"), 0);
      return;
    }
    const JsonInt modifiedIndex(node, "modifiedIndex");
    if (!modifiedIndex.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'modifiedIndex'"), 0);
      return;
    }
    CHECK_EQ(createdIndex.Value(), modifiedIndex.Value());
    cb(status, modifiedIndex.Value());
  } else {
    cb(status, -1);
  }
}

void EtcdClient::CreateInQueueRequestDone(
    Status status, const boost::shared_ptr<JsonObject>& json,
    const CreateInQueueCallback& cb) const {
  if (status.ok()) {
    const JsonObject node(*json, "node");
    if (!node.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'node'"), "", 0);
      return;
    }
    const JsonInt createdIndex(node, "createdIndex");
    if (!createdIndex.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'createdIndex'"), "", 0);
      return;
    }
    const JsonInt modifiedIndex(node, "modifiedIndex");
    if (!modifiedIndex.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'modifiedIndex'"), "", 0);
      return;
    }
    const JsonString key(node, "key");
    if (!key.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'key'"), "", 0);
      return;
    }
    CHECK_EQ(createdIndex.Value(), modifiedIndex.Value());
    cb(status, key.Value(), modifiedIndex.Value());
  } else {
    cb(status, "", -1);
  }
}

void EtcdClient::UpdateRequestDone(Status status,
                                   const boost::shared_ptr<JsonObject>& json,
                                   const UpdateCallback& cb) const {
  if (status.ok()) {
    const JsonObject node(*json, "node");
    if (!node.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'node'"), 0);
      return;
    }
    const JsonInt modifiedIndex(node, "modifiedIndex");
    if (!modifiedIndex.Ok()) {
      cb(Status(0, "Invalid JSON: Couldn't find 'modifiedIndex'"), 0);
      return;
    }
    cb(status, modifiedIndex.Value());
  } else {
    cb(status, -1);
  }
}

void EtcdClient::DeleteRequestDone(Status status,
                                   const boost::shared_ptr<JsonObject>& json,
                                   const DeleteCallback& cb) const {
  cb(status);
}

shared_ptr<libevent::HttpConnection> EtcdClient::GetConnection(
    const string& host, uint16_t port) {
  const pair<string, uint16_t> host_port(make_pair(host, port));
  const ConnectionMap::const_iterator it(conns_.find(host_port));
  shared_ptr<libevent::HttpConnection> conn;

  if (it == conns_.end()) {
    conn = make_shared<libevent::HttpConnection>(
        event_base_, UriFromHostPort(host, port).get());
    conns_.insert(make_pair(host_port, conn));
  } else {
    conn = it->second;
  }

  return conn;
}

void EtcdClient::Get(const std::string& key, const GetCallback& cb) {
  map<string, string> params;
  Generic(key, params, EVHTTP_REQ_GET,
          bind(&EtcdClient::GetRequestDone, this, _1, _2, cb));
}

void EtcdClient::GetAll(const std::string& dir, const GetAllCallback& cb) {
  map<string, string> params;
  Generic(dir, params, EVHTTP_REQ_GET,
          bind(&EtcdClient::GetAllRequestDone, this, _1, _2, cb));
}

void EtcdClient::Create(const std::string& key, const std::string& value,
                        const CreateCallback& cb) {
  map<string, string> params;
  params["value"] = value;
  params["prevExist"] = "false";
  Generic(key, params, EVHTTP_REQ_PUT,
          bind(&EtcdClient::CreateRequestDone, this, _1, _2, cb));
}

void EtcdClient::CreateInQueue(const std::string& dir, const std::string& value,
                               const CreateInQueueCallback& cb) {
  map<string, string> params;
  params["value"] = value;
  params["prevExist"] = "false";
  Generic(dir, params, EVHTTP_REQ_POST,
          bind(&EtcdClient::CreateInQueueRequestDone, this, _1, _2, cb));
}

void EtcdClient::Update(const std::string& key, const std::string& value,
                        const int previous_index, const UpdateCallback& cb) {
  map<string, string> params;
  params["value"] = value;
  params["prevIndex"] = boost::lexical_cast<string>(previous_index);
  Generic(key, params, EVHTTP_REQ_PUT,
          bind(&EtcdClient::UpdateRequestDone, this, _1, _2, cb));
}

void EtcdClient::Delete(const std::string& key, const int current_index,
                        const DeleteCallback& cb) {
  map<string, string> params;
  params["prevIndex"] = boost::lexical_cast<string>(current_index);
  Generic(key, params, EVHTTP_REQ_DELETE,
          bind(&EtcdClient::DeleteRequestDone, this, _1, _2, cb));
}

void EtcdClient::Generic(const string& key, const map<string, string>& params,
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

}  // namespace cert_trans
