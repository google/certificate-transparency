#include "util/fake_etcd.h"

#include <glog/logging.h>

#include "util/json_wrapper.h"

using std::bind;
using std::chrono::seconds;
using std::chrono::system_clock;
using std::function;
using std::lock_guard;
using std::make_shared;
using std::map;
using std::mutex;
using std::ostringstream;
using std::shared_ptr;
using std::stoi;
using std::string;
using std::to_string;
using std::vector;
using util::Status;

namespace cert_trans {
namespace {


string EnsureEndsWithSlash(const string& s) {
  if (s.empty() || s.back() != '/') {
    return s + '/';
  } else {
    return s;
  }
}


}  // namespace


class FakeEtcdClient::FakeWatcher : public EtcdClient::Watcher {
 public:
  FakeWatcher(FakeEtcdClient* client, const string& key,
              const WatchCallback& cb);

  virtual ~FakeWatcher();

 private:
  FakeEtcdClient* const client_;
  const string key_;
  const WatchCallback cb_;
};


FakeEtcdClient::FakeWatcher::FakeWatcher(FakeEtcdClient* client,
                                         const string& key,
                                         const WatchCallback& cb)
    : client_(client), key_(key), cb_(cb) {
  std::vector<Update> initial_updates;
  std::lock_guard<std::mutex> lock(client_->mutex_);
  for (const auto& pair : client_->entries_) {
    if (pair.first.find(key_) == 0) {
      initial_updates.push_back(Update(pair.second, true /*exists*/));
    }
  }
  client_->ScheduleCallback(bind(cb_, initial_updates));
  client_->watches_[key_].push_back(make_pair(cb_, static_cast<void*>(this)));
}


FakeEtcdClient::FakeWatcher::~FakeWatcher() {
  client_->RemoveWatcher(static_cast<void*>(this));
}


FakeEtcdClient::FakeEtcdClient(const std::shared_ptr<libevent::Base>& base)
    : base_(base), index_(1) {
}


void FakeEtcdClient::DumpEntries() {
  for (const auto& pair : entries_) {
    VLOG(1) << pair.second.ToString();
  }
}


EtcdClient::Watcher* FakeEtcdClient::CreateWatcher(
    const string& key, const Watcher::WatchCallback& cb) {
  return new FakeWatcher(this, key, cb);
}


void FakeEtcdClient::Generic(const string& key,
                             const map<string, string>& params,
                             evhttp_cmd_type verb, const GenericCallback& cb) {
  PurgeExpiredEntries();
  switch (verb) {
    case EVHTTP_REQ_GET:
      HandleGet(key, params, cb);
      break;
    case EVHTTP_REQ_POST:
      HandlePost(key, params, cb);
      break;
    case EVHTTP_REQ_PUT:
      HandlePut(key, params, cb);
      break;
    case EVHTTP_REQ_DELETE:
      HandleDelete(key, params, cb);
      break;
    default:
      CHECK(false) << "Unsupported verb " << verb;
  }
  DumpEntries();
}


void FillJsonForNode(const EtcdClient::Node& node, JsonObject* json) {
  json->Add("modifiedIndex", node.modified_index_);
  json->Add("createdIndex", node.created_index_);
  json->Add("key", node.key_);
  if (!node.deleted_) {
    json->Add("value", node.value_);
  }
}


void FillJsonForEntry(const EtcdClient::Node& node, const string& action,
                      JsonObject* json) {
  JsonObject json_node;
  FillJsonForNode(node, &json_node);
  json->Add("action", action);
  json->Add("node", json_node);
}


void FillJsonForDir(const vector<EtcdClient::Node>& nodes,
                    const string& action, JsonObject* json) {
  JsonObject node;
  node.Add("modifiedIndex", 1);
  node.Add("createdIndex", 1);
  node.AddBoolean("dir", true);
  if (nodes.size() > 0) {
    JsonArray json_nodes;
    for (const auto& node : nodes) {
      JsonObject json_node;
      FillJsonForNode(node, &json_node);
      json_nodes.Add(&json_node);
    }
    node.Add("nodes", json_nodes);
  }
  node.Add("action", action);
  json->Add("node", node);
}


void FakeEtcdClient::PurgeExpiredEntries() {
  lock_guard<mutex> lock(mutex_);
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (it->second.expires_ < system_clock::now()) {
      VLOG(1) << "Deleting expired entry " << it->first;
      it->second.deleted_ = true;
      NotifyForPath(it->first);
      it = entries_.erase(it);
    } else {
      ++it;
    }
  }
}


void FakeEtcdClient::NotifyForPath(const string& path) {
  VLOG(1) << "notifying " << path;
  const bool exists(entries_.find(path) != entries_.end());
  CHECK(exists);
  const Node& node(entries_.find(path)->second);
  for (const auto& pair : watches_) {
    if (path.find(pair.first) == 0) {
      for (const auto& cb_cookie : pair.second) {
        ScheduleCallback(
            bind(cb_cookie.first, vector<Watcher::Update>{
                                      Watcher::Update(node, !node.deleted_)}));
      }
    }
  }
}


void FakeEtcdClient::GetSingleEntry(const string& key,
                                    const GenericCallback& cb) {
  if (entries_.find(key) != entries_.end()) {
    const Node& node(entries_.find(key)->second);
    shared_ptr<JsonObject> json(make_shared<JsonObject>());
    FillJsonForEntry(node, "get", json.get());
    return ScheduleCallback(bind(cb, Status::OK, json, index_));
  } else {
    return ScheduleCallback(bind(cb,
                                 Status(util::error::NOT_FOUND, "not found"),
                                 make_shared<JsonObject>(), index_));
  }
}


void FakeEtcdClient::GetDirectory(const string& key,
                                  const GenericCallback& cb) {
  VLOG(1) << "GET DIR";
  CHECK(key.back() == '/');
  vector<Node> nodes;
  for (const auto& pair : entries_) {
    if (pair.first.find(key) == 0) {
      nodes.push_back(pair.second);
    }
  }
  shared_ptr<JsonObject> json(make_shared<JsonObject>());
  FillJsonForDir(nodes, "get", json.get());
  VLOG(1) << json->ToString();
  return ScheduleCallback(bind(cb, Status::OK, json, index_));
}


void FakeEtcdClient::HandleGet(const string& key,
                               const map<string, string>& params,
                               const GenericCallback& cb) {
  VLOG(1) << "GET " << key;
  lock_guard<mutex> lock(mutex_);
  if (key.back() == '/') {
    return GetDirectory(key, cb);
  } else {
    return GetSingleEntry(key, cb);
  }
}


void MaybeSetExpiry(const map<string, string>& params,
                    EtcdClient::Node* node) {
  if (params.find("ttl") != params.end()) {
    const string& ttl(params.find("ttl")->second);
    node->expires_ = system_clock::now() + seconds(stoi(ttl));
  }
}


bool GetParam(const map<string, string>& params, const string& name,
              string* out) {
  if (params.find(name) == params.end()) {
    return false;
  }
  *out = params.find(name)->second;
  return true;
}


Status FakeEtcdClient::CheckCompareFlags(const map<string, string> params,
                                         const string& key) {
  const bool entry_exists(entries_.find(key) != entries_.end());
  string prev_exist;
  if (GetParam(params, "prevExist", &prev_exist)) {
    if (entry_exists && prev_exist == "false") {
      return Status(util::error::FAILED_PRECONDITION, key + " Already exists");
    } else if (!entry_exists && prev_exist == "true") {
      return Status(util::error::FAILED_PRECONDITION, key + " Not found");
    }
  }
  string prev_index;
  if (GetParam(params, "prevIndex", &prev_index)) {
    if (!entry_exists) {
      return Status(util::error::FAILED_PRECONDITION,
                    "Node doesn't exist: " + key);
    }
    const string modified_index(to_string(entries_[key].modified_index_));
    if (prev_index != modified_index) {
      return Status(util::error::FAILED_PRECONDITION,
                    "Incorrect index:  prevIndex=" + prev_index +
                        " but modified_index_=" + modified_index);
    }
  }
  return Status::OK;
}


void FakeEtcdClient::HandlePost(const string& key,
                                const map<string, string>& params,
                                const GenericCallback& cb) {
  VLOG(1) << "POST " << key;
  lock_guard<mutex> lock(mutex_);
  const string path(EnsureEndsWithSlash(key) + to_string(index_));
  CHECK(params.find("value") != params.end());
  const string& value(params.find("value")->second);
  Node node(index_, index_, path, value);
  MaybeSetExpiry(params, &node);
  entries_[path] = node;

  ++index_;
  shared_ptr<JsonObject> json(make_shared<JsonObject>());
  FillJsonForEntry(node, "create", json.get());
  ScheduleCallback(bind(cb, Status::OK, json, index_));
  NotifyForPath(path);
}


void FakeEtcdClient::HandlePut(const string& key,
                               const map<string, string>& params,
                               const GenericCallback& cb) {
  VLOG(1) << "PUT " << key;
  lock_guard<mutex> lock(mutex_);
  CHECK(key.back() != '/');
  CHECK(params.find("value") != params.end());
  const string& value(params.find("value")->second);
  Node node(index_, index_, key, value);
  MaybeSetExpiry(params, &node);
  Status status(CheckCompareFlags(params, key));
  if (!status.ok()) {
    ScheduleCallback(bind(cb, status, make_shared<JsonObject>(), index_));
    return;
  }
  if (entries_.find(key) != entries_.end()) {
    VLOG(1) << "Keeping original created_index_";
    node.created_index_ = entries_.find(key)->second.created_index_;
  }

  entries_[key] = node;
  ++index_;
  shared_ptr<JsonObject> json(make_shared<JsonObject>());
  FillJsonForEntry(node, "set", json.get());
  ScheduleCallback(bind(cb, Status::OK, json, index_));
  NotifyForPath(key);
}


void FakeEtcdClient::HandleDelete(const string& key,
                                  const map<string, string>& params,
                                  const GenericCallback& cb) {
  VLOG(1) << "DELETE " << key;
  lock_guard<mutex> lock(mutex_);
  CHECK(key.back() != '/');
  Status status(CheckCompareFlags(params, key));
  if (!status.ok()) {
    ScheduleCallback(bind(cb, status, make_shared<JsonObject>(), index_));
    return;
  }
  entries_[key].deleted_ = true;
  ++index_;
  shared_ptr<JsonObject> json(make_shared<JsonObject>());
  FillJsonForEntry(entries_[key], "delete", json.get());
  ScheduleCallback(bind(cb, Status::OK, json, index_));
  NotifyForPath(key);
  entries_.erase(key);
}


void FakeEtcdClient::RemoveWatcher(const void* cookie) {
  lock_guard<mutex> lock(mutex_);
  for (auto& pair : watches_) {
    for (auto it(pair.second.begin()); it != pair.second.end();) {
      if (it->second == cookie) {
        VLOG(1) << "Removing watcher " << it->second << " on " << pair.first;
        it = pair.second.erase(it);
      } else {
        ++it;
      }
    }
  }
}


void FakeEtcdClient::ScheduleCallback(const function<void()>& cb) {
  base_->Add(cb);
}


}  // namespace cert_trans
