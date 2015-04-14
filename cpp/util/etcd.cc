#include "util/etcd.h"

#include <ctime>
#include <glog/logging.h>
#include <utility>

#include "util/json_wrapper.h"
#include "util/libevent_wrapper.h"
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

const char* kStoreStats[] = {"setsFail", "getsSuccess", "watchers",
                             "expireCount", "createFail", "setsSuccess",
                             "compareAndDeleteFail", "createSuccess",
                             "deleteFail", "compareAndSwapSuccess",
                             "compareAndSwapFail", "compareAndDeleteSuccess",
                             "updateFail", "deleteSuccess", "updateSuccess",
                             "getsFail"};

const char kKeysSpace[] = "/v2/keys";
const char kStatsSpace[] = "/v2/stats";

const char kStoreStatsKey[] = "/store";


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


Status StatusFromResponseCode(const int response_code,
                              const shared_ptr<JsonObject>& json) {
  const util::error::Code error_code(
      ErrorCodeForHttpResponseCode(response_code));
  const string error_message(
      error_code == util::error::OK ? "" : MessageFromJsonStatus(json));
  return Status(error_code, error_message);
}


StatusOr<EtcdClient::Node> ParseNodeFromJson(const JsonObject& json_node) {
  const JsonInt createdIndex(json_node, "createdIndex");
  if (!createdIndex.Ok()) {
    return Status(util::error::FAILED_PRECONDITION,
                  "Invalid JSON: Couldn't find 'createdIndex'");
  }

  const JsonInt modifiedIndex(json_node, "modifiedIndex");
  if (!modifiedIndex.Ok()) {
    return Status(util::error::FAILED_PRECONDITION,
                  "Invalid JSON: Couldn't find 'modifiedIndex'");
  }

  const JsonString key(json_node, "key");
  if (!key.Ok()) {
    return Status(util::error::FAILED_PRECONDITION,
                  "Invalid JSON: Couldn't find 'key'");
  }

  const JsonString value(json_node, "value");
  const JsonBoolean isDir(json_node, "dir");
  const bool is_dir(isDir.Ok() && isDir.Value());
  const bool deleted(!value.Ok() && !is_dir);
  vector<EtcdClient::Node> nodes;
  if (is_dir && !deleted) {
    const JsonArray json_nodes(json_node, "nodes");
    if (json_nodes.Ok()) {
      for (int i = 0; i < json_nodes.Length(); ++i) {
        const JsonObject json_entry(json_nodes, i);
        if (!json_entry.Ok()) {
          return Status(util::error::FAILED_PRECONDITION,
                        "Invalid JSON: Couldn't get 'nodes' index " +
                            to_string(i));
        }

        StatusOr<EtcdClient::Node> entry(ParseNodeFromJson(json_entry));
        if (!entry.status().ok()) {
          return entry.status();
        }

        if (entry.ValueOrDie().deleted_) {
          return Status(util::error::FAILED_PRECONDITION,
                        "Deleted sub-node " + string(key.Value()));
        }

        nodes.emplace_back(entry.ValueOrDie());
      }
    }
  }

  return EtcdClient::Node(createdIndex.Value(), modifiedIndex.Value(),
                          key.Value(), is_dir,
                          (deleted || is_dir) ? "" : value.Value(),
                          move(nodes), deleted);
}


void GetRequestDone(const string& keyname, EtcdClient::GetResponse* resp,
                    Task* parent_task, EtcdClient::GenericResponse* gen_resp,
                    Task* task) {
  *resp = EtcdClient::GetResponse();
  resp->etcd_index = gen_resp->etcd_index;
  if (!task->status().ok()) {
    parent_task->Return(
        Status(task->status().CanonicalCode(),
               task->status().error_message() + " (" + keyname + ")"));
    return;
  }

  const JsonObject json_node(*gen_resp->json_body, "node");
  if (!json_node.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'node'"));
    return;
  }

  StatusOr<EtcdClient::Node> node(ParseNodeFromJson(json_node));
  if (!node.status().ok()) {
    parent_task->Return(node.status());
    return;
  }

  resp->node = node.ValueOrDie();
  parent_task->Return();
}


void CopyStat(const string& key, const JsonObject& from,
              map<string, int64_t>* to) {
  CHECK_NOTNULL(to);
  const JsonInt stat(from, key.c_str());
  if (!stat.Ok()) {
    LOG(WARNING) << "Failed to find stat " << key;
    return;
  }
  (*to)[key] = stat.Value();
}


void GetStoreStatsRequestDone(EtcdClient::StatsResponse* resp,
                              Task* parent_task,
                              EtcdClient::GenericResponse* gen_resp,
                              Task* task) {
  *resp = EtcdClient::StatsResponse();
  resp->etcd_index = gen_resp->etcd_index;
  if (!task->status().ok()) {
    parent_task->Return(task->status());
    return;
  }

  if (!gen_resp->json_body->Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: json_body not Ok."));
    return;
  }

  for (const auto& stat : kStoreStats) {
    CopyStat(stat, *gen_resp->json_body, &resp->stats);
  }
  parent_task->Return();
}


void CreateRequestDone(EtcdClient::Response* resp, Task* parent_task,
                       EtcdClient::GenericResponse* gen_resp, Task* task) {
  if (!task->status().ok()) {
    parent_task->Return(task->status());
    return;
  }

  const JsonObject json_node(*gen_resp->json_body, "node");
  if (!json_node.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'node'"));
    return;
  }

  StatusOr<EtcdClient::Node> node(ParseNodeFromJson(json_node));
  if (!node.status().ok()) {
    parent_task->Return(node.status());
    return;
  }

  CHECK_EQ(node.ValueOrDie().created_index_,
           node.ValueOrDie().modified_index_);
  resp->etcd_index = node.ValueOrDie().modified_index_;
  parent_task->Return();
}


void UpdateRequestDone(EtcdClient::Response* resp, Task* parent_task,
                       EtcdClient::GenericResponse* gen_resp, Task* task) {
  *resp = EtcdClient::Response();
  if (!task->status().ok()) {
    parent_task->Return(task->status());
    return;
  }

  const JsonObject json_node(*gen_resp->json_body, "node");
  if (!json_node.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'node'"));
    return;
  }

  StatusOr<EtcdClient::Node> node(ParseNodeFromJson(json_node));
  if (!node.status().ok()) {
    parent_task->Return(node.status());
    return;
  }

  resp->etcd_index = node.ValueOrDie().modified_index_;
  parent_task->Return();
}


void ForceSetRequestDone(EtcdClient::Response* resp, Task* parent_task,
                         EtcdClient::GenericResponse* gen_resp, Task* task) {
  *resp = EtcdClient::Response();
  if (!task->status().ok()) {
    parent_task->Return(task->status());
    return;
  }

  const JsonObject json_node(*gen_resp->json_body, "node");
  if (!json_node.Ok()) {
    parent_task->Return(Status(util::error::FAILED_PRECONDITION,
                               "Invalid JSON: Couldn't find 'node'"));
    return;
  }

  StatusOr<EtcdClient::Node> node(ParseNodeFromJson(json_node));
  if (!node.status().ok()) {
    parent_task->Return(node.status());
    return;
  }

  resp->etcd_index = node.ValueOrDie().modified_index_;
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


static const EtcdClient::Node kInvalidNode(-1, -1, "", false, "", {}, true);


}  // namespace


struct EtcdClient::RequestState {
  RequestState(UrlFetcher::Verb verb, const string& key,
               const string& key_space, map<string, string> params,
               const HostPortPair& host_port, GenericResponse* gen_resp,
               Task* parent_task)
      : gen_resp_(CHECK_NOTNULL(gen_resp)),
        parent_task_(CHECK_NOTNULL(parent_task)) {
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

    req_.url.SetPath(key_space + key);
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
  Task* const parent_task_;

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

  vector<Node> nodes;
  if (resp->node.is_dir_) {
    nodes = move(resp->node.nodes_);
  } else {
    nodes.push_back(resp->node);
  }

  vector<Node> updates;
  map<string, int64_t> new_known_keys;
  VLOG(1) << "WatchGet " << state << " : num updates = " << nodes.size();
  for (const auto& node : nodes) {
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
    updates.emplace_back(Node(-1, -1, key.first, false, "", {}, true));
  }

  state->known_keys_.swap(new_known_keys);

  SendWatchUpdates(state, move(updates));
}


void EtcdClient::WatchRequestDone(WatchState* state, GetResponse* get_resp,
                                  Task* child_task) {
  // We clean up this way instead of using util::Task::DeleteWhenDone,
  // because our task is long-lived, and we do not want to accumulate
  // these objects.
  unique_ptr<GetResponse> get_resp_deleter(get_resp);

  if (state->task_->CancelRequested()) {
    state->task_->Return(Status::CANCELLED);
    return;
  }

  // Handle when the request index is too old, we have to restart the
  // watch logic (or start the watch logic the first time).
  if (!child_task ||
      (child_task->status().CanonicalCode() == util::error::ABORTED &&
       get_resp->etcd_index >= 0)) {
    // On the first time here, we don't actually have a gen_resp, we
    // just want to start the watch logic.
    if (get_resp) {
      VLOG(1) << "etcd index: " << get_resp->etcd_index;
      state->highest_index_seen_ =
          max(state->highest_index_seen_, get_resp->etcd_index);
    }

    GetResponse* const resp(new GetResponse);
    Get(state->key_, resp,
        state->task_->AddChild(
            bind(&EtcdClient::WatchInitialGetDone, this, state, resp, _1)));

    return;
  }

  // This is probably due to a timeout, just retry.
  if (!child_task->status().ok()) {
    LOG_EVERY_N(INFO, 10) << "Watch request failed: " << child_task->status();
    StartWatchRequest(state);
    return;
  }

  vector<Node> updates;
  state->highest_index_seen_ =
      max(state->highest_index_seen_, get_resp->node.modified_index_);
  updates.emplace_back(get_resp->node);

  if (!get_resp->node.deleted_) {
    state->known_keys_[get_resp->node.key_] = get_resp->node.modified_index_;
  } else {
    VLOG(1) << "erased key: " << get_resp->node.key_;
    state->known_keys_.erase(get_resp->node.key_);
  }

  SendWatchUpdates(state, move(updates));
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

  Request req(state->key_);
  req.recursive = true;
  req.wait_index = state->highest_index_seen_ + 1;

  GetResponse* const get_resp(new GetResponse);
  Get(req, get_resp, state->task_->AddChild(bind(&EtcdClient::WatchRequestDone,
                                                 this, state, get_resp, _1)));
}


EtcdClient::Node::Node(int64_t created_index, int64_t modified_index,
                       const string& key, bool is_dir, const string& value,
                       vector<Node>&& nodes, bool deleted)
    : created_index_(created_index),
      modified_index_(modified_index),
      key_(key),
      is_dir_(is_dir),
      value_(value),
      nodes_(move(nodes)),
      expires_(system_clock::time_point::max()),
      deleted_(deleted) {
  CHECK(!deleted_ || value_.empty());
  CHECK(!deleted_ || nodes_.empty());
  CHECK(!is_dir_ || value_.empty());
  CHECK(is_dir_ || nodes_.empty());
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


EtcdClient::EtcdClient(UrlFetcher* fetcher, const string& host, uint16_t port)
    : fetcher_(CHECK_NOTNULL(fetcher)), endpoint_(host, port) {
  CHECK(!endpoint_.first.empty());
  CHECK_GT(endpoint_.second, 0);
  VLOG(1) << "EtcdClient: " << this;
}


EtcdClient::EtcdClient() : fetcher_(nullptr) {
}


EtcdClient::~EtcdClient() {
  VLOG(1) << "~EtcdClient: " << this;
}


void EtcdClient::FetchDone(RequestState* etcd_req, Task* task) {
  VLOG(2) << "EtcdClient::FetchDone: " << task->status();

  if (!task->status().ok()) {
    // TODO(pphaneuf): If there is a connection problem, we should re-do the
    // request on another node.
    etcd_req->parent_task_->Return(task->status());
    return;
  } else {
    VLOG(2) << "response:\n" << etcd_req->resp_;
  }

  if (etcd_req->resp_.status_code == 307) {
    UrlFetcher::Headers::const_iterator it(
        etcd_req->resp_.headers.find("location"));

    if (it == etcd_req->resp_.headers.end()) {
      etcd_req->parent_task_->Return(
          Status(util::error::INTERNAL,
                 "etcd returned a redirect without a Location header?"));
      return;
    }

    const URL url(it->second);
    if (url.Host().empty() || url.Port() == 0) {
      etcd_req->parent_task_->Return(
          Status(util::error::INTERNAL,
                 "could not parse Location header from etcd: " + it->second));
      return;
    }

    etcd_req->SetHostPort(UpdateEndpoint(url.Host(), url.Port()));

    fetcher_->Fetch(etcd_req->req_, &etcd_req->resp_,
                    etcd_req->parent_task_->AddChild(
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

  etcd_req->parent_task_->Return(
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


void EtcdClient::Get(const Request& req, GetResponse* resp, Task* task) {
  map<string, string> params;
  if (req.recursive) {
    params["recursive"] = "true";
  }
  if (req.wait_index > 0) {
    params["wait"] = "true";
    params["waitIndex"] = to_string(req.wait_index);
    // TODO(pphaneuf): This is a hack, as "wait" is not incompatible
    // with "quorum=true". It should be left to the caller, though
    // (and I'm not sure defaulting to "quorum=true" is that good an
    // idea, even).
    params["quorum"] = "false";
  }
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(req.key, kKeysSpace, params, UrlFetcher::Verb::GET, gen_resp,
          task->AddChild(
              bind(&GetRequestDone, req.key, resp, task, gen_resp, _1)));
}


void EtcdClient::Create(const string& key, const string& value, Response* resp,
                        Task* task) {
  map<string, string> params;
  params["value"] = value;
  params["prevExist"] = "false";
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, kKeysSpace, params, UrlFetcher::Verb::PUT, gen_resp,
          task->AddChild(bind(&CreateRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::CreateWithTTL(const string& key, const string& value,
                               const seconds& ttl, Response* resp,
                               Task* task) {
  map<string, string> params;
  params["value"] = value;
  params["prevExist"] = "false";
  params["ttl"] = to_string(ttl.count());
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, kKeysSpace, params, UrlFetcher::Verb::PUT, gen_resp,
          task->AddChild(bind(&CreateRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::Update(const string& key, const string& value,
                        const int64_t previous_index, Response* resp,
                        Task* task) {
  map<string, string> params;
  params["value"] = value;
  params["prevIndex"] = to_string(previous_index);
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, kKeysSpace, params, UrlFetcher::Verb::PUT, gen_resp,
          task->AddChild(bind(&UpdateRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::UpdateWithTTL(const string& key, const string& value,
                               const seconds& ttl,
                               const int64_t previous_index, Response* resp,
                               Task* task) {
  map<string, string> params;
  params["value"] = value;
  params["prevIndex"] = to_string(previous_index);
  params["ttl"] = to_string(ttl.count());
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, kKeysSpace, params, UrlFetcher::Verb::PUT, gen_resp,
          task->AddChild(bind(&UpdateRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::ForceSet(const string& key, const string& value,
                          Response* resp, Task* task) {
  map<string, string> params;
  params["value"] = value;
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, kKeysSpace, params, UrlFetcher::Verb::PUT, gen_resp,
          task->AddChild(
              bind(&ForceSetRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::ForceSetWithTTL(const string& key, const string& value,
                                 const seconds& ttl, Response* resp,
                                 Task* task) {
  map<string, string> params;
  params["value"] = value;
  params["ttl"] = to_string(ttl.count());
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);
  Generic(key, kKeysSpace, params, UrlFetcher::Verb::PUT, gen_resp,
          task->AddChild(
              bind(&ForceSetRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::Delete(const string& key, const int64_t current_index,
                        Task* task) {
  map<string, string> params;
  params["prevIndex"] = to_string(current_index);
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);

  Generic(key, kKeysSpace, params, UrlFetcher::Verb::DELETE, gen_resp, task);
}


void EtcdClient::GetStoreStats(StatsResponse* resp, Task* task) {
  map<string, string> params;
  GenericResponse* const gen_resp(new GenericResponse);
  task->DeleteWhenDone(gen_resp);

  Generic(kStoreStatsKey, kStatsSpace, params, UrlFetcher::Verb::GET, gen_resp,
          task->AddChild(
              bind(&GetStoreStatsRequestDone, resp, task, gen_resp, _1)));
}


void EtcdClient::Watch(const string& key, const WatchCallback& cb,
                       Task* task) {
  VLOG(1) << "EtcdClient::Watch: " << key;

  WatchState* const state(new WatchState(key, cb, task));
  task->DeleteWhenDone(state);

  // This will kick off the watch logic, with an initial get request.
  WatchRequestDone(state, nullptr, nullptr);
}


void EtcdClient::Generic(const string& key, const string& key_space,
                         const map<string, string>& params,
                         UrlFetcher::Verb verb, GenericResponse* resp,
                         Task* task) {
  RequestState* const etcd_req(new RequestState(verb, key, key_space, params,
                                                GetEndpoint(), resp, task));
  task->DeleteWhenDone(etcd_req);

  fetcher_->Fetch(etcd_req->req_, &etcd_req->resp_,
                  etcd_req->parent_task_->AddChild(
                      bind(&EtcdClient::FetchDone, this, etcd_req, _1)));
}


}  // namespace cert_trans
