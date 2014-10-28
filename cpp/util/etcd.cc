#include "util/etcd.h"

#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <glog/logging.h>
#include <utility>

#include "util/json_wrapper.h"

namespace libevent = cert_trans::libevent;

using std::list;
using std::lock_guard;
using std::make_pair;
using std::make_shared;
using std::map;
using std::mutex;
using std::pair;
using std::placeholders::_1;
using std::placeholders::_2;
using std::shared_ptr;
using std::string;
using std::to_string;
using util::Status;

namespace cert_trans {

namespace {


string MessageFromJsonStatus(const shared_ptr<JsonObject>& json) {
  string message;
  const JsonString m(*json, "message");

  if (!m.Ok()) {
    message = json->DebugString();
  } else {
    message = m.Value();
  }

  return message;
}


util::error::Code ErrorCodeForHttpResponseCode(int response_code) {
  switch (response_code) {
    case 200:
    case 201:
      return util::error::OK;
    case 403:
      return util::error::PERMISSION_DENIED;
    case 404:
      return util::error::NOT_FOUND;
    case 412:
      return util::error::FAILED_PRECONDITION;
    case 500:
      return util::error::UNAVAILABLE;
    default:
      return util::error::UNKNOWN;
  }
}


Status StatusFromResponseCode(const int response_code,
                              const shared_ptr<JsonObject>& json) {
  const util::error::Code error_code(
      ErrorCodeForHttpResponseCode(response_code));
  const string error_message(
      error_code == util::error::OK ? "" : MessageFromJsonStatus(json));
  return Status(error_code, error_message);
}


shared_ptr<evhttp_uri> UriFromHostPort(const string& host, uint16_t port) {
  const shared_ptr<evhttp_uri> retval(CHECK_NOTNULL(evhttp_uri_new()),
                                      evhttp_uri_free);

  evhttp_uri_set_scheme(retval.get(), "http");
  evhttp_uri_set_host(retval.get(), host.c_str());
  evhttp_uri_set_port(retval.get(), port);

  return retval;
}


void GetRequestDone(Status status, const shared_ptr<JsonObject>& json,
                    const EtcdClient::GetCallback& cb) {
  if (status.ok()) {
    const JsonObject node(*json, "node");
    if (!node.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'node'"),
         0, "");
      return;
    }
    const JsonInt modifiedIndex(node, "modifiedIndex");
    if (!modifiedIndex.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'modifiedIndex'"),
         0, "");
      return;
    }
    const JsonString value(node, "value");
    if (!value.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'value'"),
         0, "");
      return;
    }
    cb(status, modifiedIndex.Value(), value.Value());
  } else {
    cb(status, -1, "");
  }
}


void GetAllRequestDone(Status status, const shared_ptr<JsonObject>& json,
                       const EtcdClient::GetAllCallback& cb) {
  if (status.ok()) {
    const JsonObject node(*json, "node");
    if (!node.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'node'"),
         list<pair<string, int> >());
      return;
    }
    const JsonArray value_nodes(node, "nodes");
    if (!value_nodes.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'nodes'"),
         list<pair<string, int> >());
      return;
    }
    list<pair<string, int> > values;
    for (int i = 0; i < value_nodes.Length(); ++i) {
      const JsonObject entry(value_nodes, i);
      if (!entry.Ok()) {
        cb(Status(util::error::FAILED_PRECONDITION, "Invalid JSON: Couldn't get 'value_nodes' index " + to_string(i)), list<pair<string, int> >());
        return;
      }
      const JsonString value(entry, "value");
      if (!value.Ok()) {
        cb(Status(util::error::FAILED_PRECONDITION,
                  "Invalid JSON: Couldn't find 'value'"),
           list<pair<string, int> >());
        return;
      }
      const JsonInt modifiedIndex(entry, "modifiedIndex");
      if (!modifiedIndex.Ok()) {
        cb(Status(util::error::FAILED_PRECONDITION,
                  "Invalid JSON: Coulnd't find 'modifiedIndex'"),
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


void CreateRequestDone(Status status, const shared_ptr<JsonObject>& json,
                       const EtcdClient::CreateCallback& cb) {
  if (status.ok()) {
    const JsonObject node(*json, "node");
    if (!node.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'node'"),
         0);
      return;
    }
    const JsonInt createdIndex(node, "createdIndex");
    if (!createdIndex.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'createdIndex'"),
         0);
      return;
    }
    const JsonInt modifiedIndex(node, "modifiedIndex");
    if (!modifiedIndex.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'modifiedIndex'"),
         0);
      return;
    }
    CHECK_EQ(createdIndex.Value(), modifiedIndex.Value());
    cb(status, modifiedIndex.Value());
  } else {
    cb(status, -1);
  }
}


void CreateInQueueRequestDone(Status status,
                              const shared_ptr<JsonObject>& json,
                              const EtcdClient::CreateInQueueCallback& cb) {
  if (status.ok()) {
    const JsonObject node(*json, "node");
    if (!node.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'node'"),
         "", 0);
      return;
    }
    const JsonInt createdIndex(node, "createdIndex");
    if (!createdIndex.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'createdIndex'"),
         "", 0);
      return;
    }
    const JsonInt modifiedIndex(node, "modifiedIndex");
    if (!modifiedIndex.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'modifiedIndex'"),
         "", 0);
      return;
    }
    const JsonString key(node, "key");
    if (!key.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'key'"),
         "", 0);
      return;
    }
    CHECK_EQ(createdIndex.Value(), modifiedIndex.Value());
    cb(status, key.Value(), modifiedIndex.Value());
  } else {
    cb(status, "", -1);
  }
}


void UpdateRequestDone(Status status, const shared_ptr<JsonObject>& json,
                       const EtcdClient::UpdateCallback& cb) {
  if (status.ok()) {
    const JsonObject node(*json, "node");
    if (!node.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'node'"),
         0);
      return;
    }
    const JsonInt modifiedIndex(node, "modifiedIndex");
    if (!modifiedIndex.Ok()) {
      cb(Status(util::error::FAILED_PRECONDITION,
                "Invalid JSON: Couldn't find 'modifiedIndex'"),
         0);
      return;
    }
    cb(status, modifiedIndex.Value());
  } else {
    cb(status, -1);
  }
}


string UrlEscapeAndJoinParams(const map<string, string>& params) {
  string retval;

  bool first(true);
  for (map<string, string>::const_iterator it = params.begin();
       it != params.end(); ++it) {
    if (first)
      first = false;
    else
      retval += "&";

    retval += evhttp_uriencode(it->first.c_str(), it->first.size(), 0);
    retval += "=";
    retval += evhttp_uriencode(it->second.c_str(), it->second.size(), 0);
  }

  return retval;
}


}  // namespace


struct EtcdClient::Request {
  Request(EtcdClient* client, evhttp_cmd_type verb, const string& key,
          const map<string, string>& params, const GenericCallback& cb)
      : client_(client),
        verb_(verb),
        path_("/v2/keys" + key),
        params_(UrlEscapeAndJoinParams(params)),
        cb_(cb) {
    CHECK(!key.empty());
    CHECK_EQ(key[0], '/');
  }

  void Run(const shared_ptr<libevent::HttpConnection>& conn) {
    libevent::HttpRequest* const req(new libevent::HttpRequest(
        bind(&EtcdClient::RequestDone, client_, _1, this)));

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

  EtcdClient* const client_;
  const evhttp_cmd_type verb_;
  const string path_;
  const string params_;
  const GenericCallback cb_;
};


EtcdClient::EtcdClient(const shared_ptr<libevent::Base>& event_base,
                       const string& host, uint16_t port)
    : event_base_(event_base), leader_(GetConnection(host, port)) {
  LOG(INFO) << "EtcdClient: " << this;
}


EtcdClient::EtcdClient() {
}


EtcdClient::~EtcdClient() {
  LOG(INFO) << "~EtcdClient: " << this;
}


bool EtcdClient::MaybeUpdateLeader(libevent::HttpRequest* req,
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


void EtcdClient::RequestDone(libevent::HttpRequest* req, Request* etcd_req) {
  if (!req) {
    LOG(ERROR) << "an unknown error occurred";
    etcd_req->cb_(Status(util::error::UNKNOWN, "unknown error"),
                  shared_ptr<JsonObject>());
    delete etcd_req;
    return;
  }

  if (MaybeUpdateLeader(req, etcd_req)) {
    return;
  }

  const int response_code(evhttp_request_get_response_code(req->get()));
  shared_ptr<JsonObject> json(
      make_shared<JsonObject>(evhttp_request_get_input_buffer(req->get())));
  etcd_req->cb_(StatusFromResponseCode(response_code, json), json);
  delete etcd_req;
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


void EtcdClient::Get(const string& key, const GetCallback& cb) {
  map<string, string> params;
  Generic(key, params, EVHTTP_REQ_GET, bind(&GetRequestDone, _1, _2, cb));
}


void EtcdClient::GetAll(const string& dir, const GetAllCallback& cb) {
  map<string, string> params;
  Generic(dir, params, EVHTTP_REQ_GET, bind(&GetAllRequestDone, _1, _2, cb));
}


void EtcdClient::Create(const string& key, const string& value,
                        const CreateCallback& cb) {
  map<string, string> params;
  params["value"] = value;
  params["prevExist"] = "false";
  Generic(key, params, EVHTTP_REQ_PUT, bind(&CreateRequestDone, _1, _2, cb));
}


void EtcdClient::CreateInQueue(const string& dir, const string& value,
                               const CreateInQueueCallback& cb) {
  map<string, string> params;
  params["value"] = value;
  params["prevExist"] = "false";
  Generic(dir, params, EVHTTP_REQ_POST,
          bind(&CreateInQueueRequestDone, _1, _2, cb));
}


void EtcdClient::Update(const string& key, const string& value,
                        const int previous_index, const UpdateCallback& cb) {
  map<string, string> params;
  params["value"] = value;
  params["prevIndex"] = to_string(previous_index);
  Generic(key, params, EVHTTP_REQ_PUT, bind(&UpdateRequestDone, _1, _2, cb));
}


void EtcdClient::Delete(const string& key, const int current_index,
                        const DeleteCallback& cb) {
  map<string, string> params;
  params["prevIndex"] = to_string(current_index);
  Generic(key, params, EVHTTP_REQ_DELETE, bind(cb, _1));
}


void EtcdClient::Generic(const string& key, const map<string, string>& params,
                         evhttp_cmd_type verb, const GenericCallback& cb) {
  Request* const etcd_req(new Request(this, verb, key, params, cb));
  shared_ptr<libevent::HttpConnection> conn;
  {
    lock_guard<mutex> lock(lock_);
    conn = leader_;
  }
  etcd_req->Run(conn);
}


}  // namespace cert_trans
