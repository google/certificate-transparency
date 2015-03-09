#include "util/etcd.h"

#include <ctime>
#include <glog/logging.h>
#include <utility>

#include "util/json_wrapper.h"
#include "util/statusor.h"

namespace libevent = cert_trans::libevent;

using std::atoll;
using std::bind;
using std::chrono::seconds;
using std::chrono::system_clock;
using std::ctime;
using std::lock_guard;
using std::make_pair;
using std::make_shared;
using std::map;
using std::max;
using std::move;
using std::mutex;
using std::ostringstream;
using std::placeholders::_1;
using std::shared_ptr;
using std::string;
using std::time_t;
using std::to_string;
using std::unique_ptr;
using std::vector;
using util::Status;
using util::StatusOr;
using util::Task;

DEFINE_int32(etcd_watch_error_retry_delay_seconds, 5,
             "delay between retrying etcd watch requests");
DEFINE_bool(etcd_consistent, true, "Add consistent=true param to all requests. "
            "Do not turn this off unless you *know* what you're doing.");
DEFINE_bool(etcd_quorum, true, "Add quorum=true param to all requests. "
            "Do not turn this off unless you *know* what you're doing.");
DEFINE_int32(etcd_connection_timeout_seconds, 10,
             "Number of seconds after which to timeout etcd connections.");

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
    case 400:
      return util::error::ABORTED;
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


bool KeyIsDirectory(const string& key) {
  return key.size() > 0 && key.back() == '/';
}


Status StatusFromResponseCode(const int response_code,
                              const shared_ptr<JsonObject>& json) {
  const util::error::Code error_code(
      ErrorCodeForHttpResponseCode(response_code));
  const string error_message(
      error_code == util::error::OK ? "" : MessageFromJsonStatus(json));
  return Status(error_code, error_message);
}


void GetRequestDone(const string& keyname, EtcdClient::GetResponse* resp,
                    Task* parent_task, EtcdClient::GenericResponse* gen_resp,
                    Task* task) {
  *resp = EtcdClient::GetResponse();
  if (!task->status().ok()) {
    parent_task->Return(
        Status(task->status().CanonicalCode(),
               task->status().error_message() + " (" + keyname + ")"));
    return;
  }

  const JsonObject node(*gen_resp->json_body, "node");
  if (!node.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'node'"));
    return;
  }

  const JsonInt createdIndex(node, "createdIndex");
  if (!createdIndex.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'createdIndex'"));
    return;
  }

  const JsonInt modifiedIndex(node, "modifiedIndex");
  if (!modifiedIndex.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'modifiedIndex'"));
    return;
  }

  const JsonString key(node, "key");
  if (!key.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'key'"));
    return;
  }

  const JsonString value(node, "value");
  if (!value.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'value'"));
    return;
  }

  resp->etcd_index = gen_resp->etcd_index;
  resp->node = EtcdClient::Node(createdIndex.Value(), modifiedIndex.Value(),
                                key.Value(), value.Value(), false);
  parent_task->Return();
}


void GetAllRequestDone(const string& dir, EtcdClient::GetAllResponse* resp,
                       Task* parent_task,
                       EtcdClient::GenericResponse* gen_resp, Task* task) {
  *resp = EtcdClient::GetAllResponse();
  if (!task->status().ok()) {
    parent_task->Return(
        Status(task->status().CanonicalCode(),
               task->status().error_message() + " (" + dir + ")"));
    return;
  }

  const JsonObject node(*gen_resp->json_body, "node");
  if (!node.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'node'"));
    return;
  }

  const JsonBoolean isDir(node, "dir");
  if (!isDir.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'dir'"));
    return;
  }

  if (!isDir.Value()) {
    parent_task->Return(
        Status(util::error::INVALID_ARGUMENT, "Not a directory"));
    return;
  }

  const JsonArray value_nodes(node, "nodes");
  if (!value_nodes.Ok()) {
    // Directory is empty.
    resp->etcd_index = gen_resp->etcd_index;
    parent_task->Return();
    return;
  }

  vector<EtcdClient::Node> values;
  for (int i = 0; i < value_nodes.Length(); ++i) {
    const JsonObject entry(value_nodes, i);
    if (!entry.Ok()) {
      parent_task->Return(Status(
          util::error::FAILED_PRECONDITION,
          "Invalid JSON: Couldn't get 'value_nodes' index " + to_string(i)));
      return;
    }

    const JsonString value(entry, "value");
    if (!value.Ok()) {
      parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                                 "Invalid JSON: Couldn't find 'value'"));
      return;
    }

    const JsonInt createdIndex(entry, "createdIndex");
    if (!createdIndex.Ok()) {
      parent_task->Return(
          Status(util::error::FAILED_PRECONDITION,
                 "Invalid JSON: Coulnd't find 'createdIndex'"));
      return;
    }

    const JsonInt modifiedIndex(entry, "modifiedIndex");
    if (!modifiedIndex.Ok()) {
      parent_task->Return(
          Status(util::error::FAILED_PRECONDITION,
                 "Invalid JSON: Coulnd't find 'modifiedIndex'"));
      return;
    }

    const JsonString key(entry, "key");
    if (!key.Ok()) {
      parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                                 "Invalid JSON: Couldn't find 'key'"));
      return;
    }

    values.emplace_back(EtcdClient::Node(createdIndex.Value(),
                                         modifiedIndex.Value(), key.Value(),
                                         value.Value(), false));
  }

  resp->etcd_index = gen_resp->etcd_index;
  resp->nodes = move(values);
  parent_task->Return();
}


void CreateRequestDone(EtcdClient::Response* resp, Task* parent_task,
                       EtcdClient::GenericResponse* gen_resp, Task* task) {
  if (!task->status().ok()) {
    parent_task->Return(task->status());
    return;
  }

  const JsonObject node(*gen_resp->json_body, "node");
  if (!node.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'node'"));
    return;
  }

  const JsonInt createdIndex(node, "createdIndex");
  if (!createdIndex.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'createdIndex'"));
    return;
  }

  const JsonInt modifiedIndex(node, "modifiedIndex");
  if (!modifiedIndex.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'modifiedIndex'"));
    return;
  }

  CHECK_EQ(createdIndex.Value(), modifiedIndex.Value());
  resp->etcd_index = modifiedIndex.Value();
  parent_task->Return();
}


void CreateInQueueRequestDone(EtcdClient::CreateInQueueResponse* resp,
                              Task* parent_task,
                              EtcdClient::GenericResponse* gen_resp,
                              Task* task) {
  *resp = EtcdClient::CreateInQueueResponse();
  if (!task->status().ok()) {
    parent_task->Return(task->status());
    return;
  }

  const JsonObject node(*gen_resp->json_body, "node");
  if (!node.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'node'"));
    return;
  }

  const JsonInt createdIndex(node, "createdIndex");
  if (!createdIndex.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'createdIndex'"));
    return;
  }

  const JsonInt modifiedIndex(node, "modifiedIndex");
  if (!modifiedIndex.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'modifiedIndex'"));
    return;
  }

  const JsonString key(node, "key");
  if (!key.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'key'"));
    return;
  }

  CHECK_EQ(createdIndex.Value(), modifiedIndex.Value());
  resp->etcd_index = modifiedIndex.Value();
  resp->key = key.Value();
  parent_task->Return();
}


void UpdateRequestDone(EtcdClient::Response* resp, Task* parent_task,
                       EtcdClient::GenericResponse* gen_resp, Task* task) {
  *resp = EtcdClient::Response();
  if (!task->status().ok()) {
    parent_task->Return(task->status());
    return;
  }

  const JsonObject node(*gen_resp->json_body, "node");
  if (!node.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'node'"));
    return;
  }

  const JsonInt modifiedIndex(node, "modifiedIndex");
  if (!modifiedIndex.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'modifiedIndex'"));
    return;
  }

  resp->etcd_index = modifiedIndex.Value();
  parent_task->Return();
}


void ForceSetRequestDone(EtcdClient::Response* resp, Task* parent_task,
                         EtcdClient::GenericResponse* gen_resp, Task* task) {
  *resp = EtcdClient::Response();
  if (!task->status().ok()) {
    parent_task->Return(task->status());
    return;
  }

  const JsonObject node(*gen_resp->json_body, "node");
  if (!node.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'node'"));
    return;
  }

  const JsonInt modifiedIndex(node, "modifiedIndex");
  if (!modifiedIndex.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'modifiedIndex'"));
    return;
  }

  resp->etcd_index = modifiedIndex.Value();
  parent_task->Return();
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

    unique_ptr<char, void (*)(void*)> first(
        evhttp_uriencode(it->first.c_str(), it->first.size(), 0), &free);
    unique_ptr<char, void (*)(void*)> second(
        evhttp_uriencode(it->second.c_str(), it->second.size(), 0), &free);

    retval += first.get();
    retval += "=";
    retval += second.get();
  }

  return retval;
}


static const EtcdClient::Node kInvalidNode(-1, -1, "", "", true);


}  // namespace


struct EtcdClient::Request {
  Request(UrlFetcher::Verb verb, const string& key, map<string, string> params,
          const HostPortPair& host_port, GenericResponse* gen_resp, Task* task)
      : gen_resp_(CHECK_NOTNULL(gen_resp)), task_(CHECK_NOTNULL(task)) {
    CHECK(!key.empty());
    CHECK_EQ(key[0], '/');

    req_.verb = verb;
    SetHostPort(host_port);

    if (FLAGS_etcd_consistent) {
      params.insert(make_pair("consistent", "true"));
    } else {
      LOG_EVERY_N(WARNING, 100) << "Sending request without 'consistent=true'";
    }
    if (FLAGS_etcd_quorum) {
      params.insert(make_pair("quorum", "true"));
    } else {
      LOG_EVERY_N(WARNING, 100) << "Sending request without 'quorum=true'";
    }

    req_.url.SetPath("/v2/keys" + key);
    switch (req_.verb) {
      case UrlFetcher::Verb::POST:
      case UrlFetcher::Verb::PUT:
        req_.headers.insert(
            make_pair("Content-Type", "application/x-www-form-urlencoded"));
        req_.body = UrlEscapeAndJoinParams(params);
        break;

      default:
        req_.url.SetQuery(UrlEscapeAndJoinParams(params));
    }
    VLOG(2) << "path query: " << req_.url.PathQuery();
  }

  void SetHostPort(const HostPortPair& host_port) {
    CHECK(!host_port.first.empty());
    CHECK_GT(host_port.second, 0);
    req_.url.SetProtocol("http");
    req_.url.SetHost(host_port.first);
    req_.url.SetPort(host_port.second);
  }

  GenericResponse* const gen_resp_;
  Task* const task_;

  UrlFetcher::Request req_;
  UrlFetcher::Response resp_;
};


struct EtcdClient::WatchState {
  WatchState(const string& key, const WatchCallback& cb, Task* task)
      : key_(key),
        cb_(cb),
        task_(CHECK_NOTNULL(task)),
        highest_index_seen_(-1) {
  }

  ~WatchState() {
    VLOG(1) << "EtcdClient::Watch: no longer watching " << key_;
  }

  const string key_;
  const WatchCallback cb_;
  Task* const task_;

  int64_t highest_index_seen_;
  map<string, int64_t> known_keys_;
};


void EtcdClient::WatchInitialGetDone(WatchState* state, GetResponse* resp,
                                     Task* task) {
  unique_ptr<GetResponse> resp_deleter(resp);
  GetAllResponse* const all_resp(new GetAllResponse);
  all_resp->etcd_index = resp->etcd_index;
  if (task->status().ok()) {
    all_resp->nodes = {resp->node};
  }
  WatchInitialGetAllDone(state, all_resp, task);
}


void EtcdClient::WatchInitialGetAllDone(WatchState* state,
                                        GetAllResponse* resp, Task* task) {
  unique_ptr<GetAllResponse> resp_deleter(resp);
  if (state->task_->CancelRequested()) {
    state->task_->Return(Status::CANCELLED);
    return;
  }

  // TODO(pphaneuf): Need better error handling here. Have to review
  // what the possible errors are, most of them should probably be
  // dealt with using retries?
  CHECK(task->status().ok()) << "initial get error: " << task->status();

  state->highest_index_seen_ =
      max(state->highest_index_seen_, resp->etcd_index);

  vector<Node> updates;
  map<string, int64_t> new_known_keys;
  VLOG(1) << "WatchGet " << state << " : num updates = " << resp->nodes.size();
  for (const auto& node : resp->nodes) {
    // This simply shouldn't happen, but since I think it shouldn't
    // prevent us from continuing processing, CHECKing on this would
    // just be mean...
    LOG_IF(WARNING, resp->etcd_index < node.modified_index_)
        << "X-Etcd-Index (" << resp->etcd_index
        << ") smaller than node modifiedIndex (" << node.modified_index_
        << ") for key \"" << node.key_ << "\"";

    map<string, int64_t>::iterator it(state->known_keys_.find(node.key_));
    if (it == state->known_keys_.end() || it->second < node.modified_index_) {
      VLOG(1) << "WatchGet " << state << " : updated node " << node.key_
              << " @ " << node.modified_index_;
      // Nodes received in an initial get should *always* exist!
      CHECK(!node.deleted_);
      updates.emplace_back(node);
    }

    new_known_keys[node.key_] = node.modified_index_;
    if (it != state->known_keys_.end()) {
      VLOG(1) << "WatchGet " << state << " : stale update " << node.key_
              << " @ " << node.modified_index_;
      state->known_keys_.erase(it);
    }
  }

  // The keys still in known_keys_ at this point have been deleted.
  for (const auto& key : state->known_keys_) {
    // TODO(pphaneuf): Passing in -1 for the created and modified
    // indices, is that a problem? We do have a "last known" modified
    // index in key.second...
    updates.emplace_back(Node(-1, -1, key.first, "", true));
  }

  state->known_keys_.swap(new_known_keys);

  state->task_->executor()->Add(
      bind(&EtcdClient::SendWatchUpdates, this, state, move(updates)));
}


StatusOr<EtcdClient::Node> UpdateForNode(const JsonObject& node) {
  const JsonInt createdIndex(node, "createdIndex");
  if (!createdIndex.Ok()) {
    return Status(util::error::FAILED_PRECONDITION,
                  "Invalid JSON: Couldn't find 'createdIndex'");
  }

  const JsonInt modifiedIndex(node, "modifiedIndex");
  if (!modifiedIndex.Ok()) {
    return Status(util::error::FAILED_PRECONDITION,
                  "Invalid JSON: Couldn't find 'modifiedIndex'");
  }

  const JsonString key(node, "key");
  if (!key.Ok()) {
    return Status(util::error::FAILED_PRECONDITION,
                  "Invalid JSON: Couldn't find 'key'");
  }

  const JsonString value(node, "value");
  if (value.Ok()) {
    return EtcdClient::Node(createdIndex.Value(), modifiedIndex.Value(),
                            key.Value(), value.Value(), false);
  } else {
    return EtcdClient::Node(createdIndex.Value(), modifiedIndex.Value(),
                            key.Value(), "", true);
  }
}


void EtcdClient::WatchRequestDone(WatchState* state, GenericResponse* gen_resp,
                                  Task* child_task) {
  // We clean up this way instead of using util::Task::DeleteWhenDone,
  // because our task is long-lived, and we do not want to accumulate
  // these objects.
  unique_ptr<GenericResponse> gen_resp_deleter(gen_resp);

  if (state->task_->CancelRequested()) {
    state->task_->Return(Status::CANCELLED);
    return;
  }

  // Handle when the request index is too old, we have to restart the
  // watch logic (or start the watch logic the first time).
  if (!child_task ||
      (child_task->status().CanonicalCode() == util::error::ABORTED &&
       gen_resp->etcd_index >= 0)) {
    // On the first time here, we don't actually have a gen_resp, we
    // just want to start the watch logic.
    if (gen_resp) {
      VLOG(1) << "etcd index: " << gen_resp->etcd_index;
      state->highest_index_seen_ =
          max(state->highest_index_seen_, gen_resp->etcd_index);
    }

    if (KeyIsDirectory(state->key_)) {
      GetAllResponse* const resp(new GetAllResponse);
      GetAll(state->key_, resp,
             state->task_->AddChild(bind(&EtcdClient::WatchInitialGetAllDone,
                                         this, state, resp, _1)));
    } else {
      GetResponse* const resp(new GetResponse);
      Get(state->key_, resp,
          state->task_->AddChild(
              bind(&EtcdClient::WatchInitialGetDone, this, state, resp, _1)));
    }

    return;
  }

  // TODO(pphaneuf): This and many other of the callbacks in this file
  // do very similar validation, we should pull that out in a shared
  // helper function.
  {
    // This is probably due to a timeout, just retry.
    if (!child_task->status().ok()) {
      LOG_EVERY_N(INFO, 10)
          << "Watch request failed: " << child_task->status();
      goto fail;
    }

    // TODO(pphaneuf): None of this should ever happen, so I'm not
    // sure what's the best way to handle it? CHECK-fail? Retry? With
    // a delay? Retrying for now...
    const JsonObject node(*gen_resp->json_body, "node");
    if (!node.Ok()) {
      LOG(INFO) << "Invalid JSON: Couldn't find 'node'";
      goto fail;
    }

    vector<Node> updates;
    StatusOr<Node> status(UpdateForNode(node));
    if (!status.ok()) {
      LOG(INFO) << "UpdateForNode failed: " << status.status();
      goto fail;
    }
    state->highest_index_seen_ =
        max(state->highest_index_seen_, status.ValueOrDie().modified_index_);
    updates.emplace_back(status.ValueOrDie());

    if (!status.ValueOrDie().deleted_) {
      state->known_keys_[status.ValueOrDie().key_] =
          status.ValueOrDie().modified_index_;
    } else {
      LOG(INFO) << "erased key: " << status.ValueOrDie().key_;
      state->known_keys_.erase(status.ValueOrDie().key_);
    }

    return state->task_->executor()->Add(
        bind(&EtcdClient::SendWatchUpdates, this, state, move(updates)));
  }

fail:
  event_base_->Delay(seconds(FLAGS_etcd_watch_error_retry_delay_seconds),
                     state->task_->AddChild(
                         bind(&EtcdClient::StartWatchRequest, this, state)));
}


// This method should always be called on the executor of
// state->task_.
void EtcdClient::SendWatchUpdates(WatchState* state,
                                  const vector<Node>& updates) {
  if (!updates.empty() || state->highest_index_seen_ == -1) {
    state->cb_(updates);
  }

  // Only start the next request once the callback has return, to make
  // sure they are always delivered in order.
  StartWatchRequest(state);
}


void EtcdClient::StartWatchRequest(WatchState* state) {
  if (state->task_->CancelRequested()) {
    state->task_->Return(Status::CANCELLED);
    return;
  }

  map<string, string> params;
  params["wait"] = "true";
  params["quorum"] = "false";
  params["waitIndex"] = to_string(state->highest_index_seen_ + 1);
  params["recursive"] = "true";

  GenericResponse* const gen_resp(new GenericResponse);
  Generic(state->key_, params, UrlFetcher::Verb::GET, gen_resp,
          state->task_->AddChild(
              bind(&EtcdClient::WatchRequestDone, this, state, gen_resp, _1)));
}


EtcdClient::Node::Node(int64_t created_index, int64_t modified_index,
                       const string& key, const string& value, bool deleted)
    : created_index_(created_index),
      modified_index_(modified_index),
      key_(key),
      value_(value),
      expires_(system_clock::time_point::max()),
      deleted_(deleted) {
}


// static
const EtcdClient::Node& EtcdClient::Node::InvalidNode() {
  return kInvalidNode;
}


string EtcdClient::Node::ToString() const {
  ostringstream oss;
  oss << "[" << key_ << ": '" << value_ << "' c: " << created_index_
      << " m: " << modified_index_;
  if (HasExpiry()) {
    time_t time_c = system_clock::to_time_t(expires_);
    oss << " expires: " << ctime(&time_c);
  }
  oss << " deleted: " << deleted_ << "]";
  return oss.str();
}


bool EtcdClient::Node::HasExpiry() const {
  return expires_ < system_clock::time_point::max();
}


EtcdClient::EtcdClient(const shared_ptr<libevent::Base>& event_base,
                       UrlFetcher* fetcher, const string& host, uint16_t port)
    : event_base_(event_base),
      fetcher_(CHECK_NOTNULL(fetcher)),
      endpoint_(host, port) {
  CHECK_NOTNULL(event_base_.get());
  CHECK(!endpoint_.first.empty());
  CHECK_GT(endpoint_.second, 0);
  VLOG(1) << "EtcdClient: " << this;
}


EtcdClient::EtcdClient(const shared_ptr<libevent::Base>& event_base)
    : event_base_(event_base), fetcher_(nullptr) {
  CHECK_NOTNULL(event_base_.get());
}


EtcdClient::~EtcdClient() {
  VLOG(1) << "~EtcdClient: " << this;
}


void EtcdClient::FetchDone(Request* etcd_req, util::Task* task) {
  VLOG(2) << "EtcdClient::FetchDone: " << task->status();

  if (!task->status().ok()) {
    // TODO(pphaneuf): If there is a connection problem, we should re-do the
    // request on another node.
    etcd_req->task_->Return(task->status());
    return;
  } else {
    VLOG(2) << "response:\n" << etcd_req->resp_;
  }

  if (etcd_req->resp_.status_code == 307) {
    UrlFetcher::Headers::const_iterator it(
        etcd_req->resp_.headers.find("location"));

    if (it == etcd_req->resp_.headers.end()) {
      etcd_req->task_->Return(
          Status(util::error::INTERNAL,
                 "etcd returned a redirect without a Location header?"));
      return;
    }

    const URL url(it->second);
    if (url.Host().empty() || url.Port() == 0) {
      etcd_req->task_->Return(
          Status(util::error::INTERNAL,
                 "could not parse Location header from etcd: " + it->second));
      return;
    }

    etcd_req->SetHostPort(UpdateEndpoint(url.Host(), url.Port()));

    fetcher_->Fetch(etcd_req->req_, &etcd_req->resp_,
                    etcd_req->task_->AddChild(
                        bind(&EtcdClient::FetchDone, this, etcd_req, _1)));
    return;
  }

  etcd_req->gen_resp_->json_body =
      make_shared<JsonObject>(etcd_req->resp_.body);
  etcd_req->gen_resp_->etcd_index = -1;

  UrlFetcher::Headers::const_iterator it(
      etcd_req->resp_.headers.find("X-Etcd-Index"));
  if (it != etcd_req->resp_.headers.end()) {
    etcd_req->gen_resp_->etcd_index = atoll(it->second.c_str());
  }

  etcd_req->task_->Return(
      StatusFromResponseCode(etcd_req->resp_.status_code,
                             etcd_req->gen_resp_->json_body));
}


EtcdClient::HostPortPair EtcdClient::GetEndpoint() const {
  lock_guard<mutex> lock(lock_);
  return endpoint_;
}


EtcdClient::HostPortPair EtcdClient::UpdateEndpoint(const string& host,
                                                    uint16_t port) {
  lock_guard<mutex> lock(lock_);
  VLOG_IF(1, endpoint_.first != host || endpoint_.second != port)
      << "new endpoint: " << host << ":" << port;
  endpoint_ = make_pair(host, port);
  return endpoint_;
}


void EtcdClient::Get(const string& key, GetResponse* resp, Task* task) {
  map<string, string> params;
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, params, UrlFetcher::Verb::GET, gen_resp,
          task->AddChild(
              bind(&GetRequestDone, key, resp, task, gen_resp, _1)));
}


void EtcdClient::GetAll(const string& dir, GetAllResponse* resp, Task* task) {
  map<string, string> params;
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(dir, params, UrlFetcher::Verb::GET, gen_resp,
          task->AddChild(
              bind(&GetAllRequestDone, dir, resp, task, gen_resp, _1)));
}


void EtcdClient::Create(const string& key, const string& value, Response* resp,
                        util::Task* task) {
  map<string, string> params;
  params["value"] = value;
  params["prevExist"] = "false";
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, params, UrlFetcher::Verb::PUT, gen_resp,
          task->AddChild(bind(&CreateRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::CreateWithTTL(const string& key, const string& value,
                               const seconds& ttl, Response* resp,
                               util::Task* task) {
  map<string, string> params;
  params["value"] = value;
  params["prevExist"] = "false";
  params["ttl"] = to_string(ttl.count());
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, params, UrlFetcher::Verb::PUT, gen_resp,
          task->AddChild(bind(&CreateRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::CreateInQueue(const string& dir, const string& value,
                               CreateInQueueResponse* resp, Task* task) {
  map<string, string> params;
  params["value"] = value;
  params["prevExist"] = "false";
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(dir, params, UrlFetcher::Verb::POST, gen_resp,
          task->AddChild(
              bind(&CreateInQueueRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::Update(const string& key, const string& value,
                        const int64_t previous_index, Response* resp,
                        util::Task* task) {
  map<string, string> params;
  params["value"] = value;
  params["prevIndex"] = to_string(previous_index);
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, params, UrlFetcher::Verb::PUT, gen_resp,
          task->AddChild(bind(&UpdateRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::UpdateWithTTL(const string& key, const string& value,
                               const seconds& ttl,
                               const int64_t previous_index, Response* resp,
                               util::Task* task) {
  map<string, string> params;
  params["value"] = value;
  params["prevIndex"] = to_string(previous_index);
  params["ttl"] = to_string(ttl.count());
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, params, UrlFetcher::Verb::PUT, gen_resp,
          task->AddChild(bind(&UpdateRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::ForceSet(const string& key, const string& value,
                          Response* resp, util::Task* task) {
  map<string, string> params;
  params["value"] = value;
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, params, UrlFetcher::Verb::PUT, gen_resp,
          task->AddChild(
              bind(&ForceSetRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::ForceSetWithTTL(const string& key, const string& value,
                                 const seconds& ttl, Response* resp,
                                 util::Task* task) {
  map<string, string> params;
  params["value"] = value;
  params["ttl"] = to_string(ttl.count());
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, params, UrlFetcher::Verb::PUT, gen_resp,
          task->AddChild(
              bind(&ForceSetRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::Delete(const string& key, const int64_t current_index,
                        Task* task) {
  map<string, string> params;
  params["prevIndex"] = to_string(current_index);
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);

  Generic(key, params, UrlFetcher::Verb::DELETE, gen_resp, task);
}


void EtcdClient::Watch(const string& key, const WatchCallback& cb,
                       Task* task) {
  VLOG(1) << "EtcdClient::Watch: " << key;

  WatchState* const state(new WatchState(key, cb, task));
  task->DeleteWhenDone(state);

  // This will kick off the watch logic, with an initial get request.
  WatchRequestDone(state, nullptr, nullptr);
}


void EtcdClient::Generic(const string& key, const map<string, string>& params,
                         UrlFetcher::Verb verb, GenericResponse* resp,
                         Task* task) {
  Request* const etcd_req(
      new Request(verb, key, params, GetEndpoint(), resp, task));
  task->DeleteWhenDone(etcd_req);

  fetcher_->Fetch(etcd_req->req_, &etcd_req->resp_,
                  etcd_req->task_->AddChild(
                      bind(&EtcdClient::FetchDone, this, etcd_req, _1)));
}


}  // namespace cert_trans
