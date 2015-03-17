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
using std::move;
using std::mutex;
using std::ostringstream;
using std::shared_ptr;
using std::stoi;
using std::string;
using std::to_string;
using std::unique_lock;
using std::vector;
using util::Status;
using util::Task;

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


FakeEtcdClient::FakeEtcdClient(const std::shared_ptr<libevent::Base>& base)
    : EtcdClient(base), base_(base), index_(1) {
}


void FakeEtcdClient::DumpEntries() {
  for (const auto& pair : entries_) {
    VLOG(1) << pair.second.ToString();
  }
}


void FakeEtcdClient::Watch(const string& key, const WatchCallback& cb,
                           Task* task) {
  unique_lock<mutex> lock(mutex_);
  vector<Node> initial_updates;
  for (const auto& pair : entries_) {
    if (pair.first.find(key) == 0) {
      CHECK(!pair.second.deleted_);
      initial_updates.emplace_back(pair.second);
    }
  }
  ScheduleWatchCallback(lock, task, bind(cb, move(initial_updates)));
  watches_[key].push_back(make_pair(cb, task));
  task->WhenCancelled(bind(&FakeEtcdClient::CancelWatch, this, task));
}


void FakeEtcdClient::Generic(const std::string& key,
                             const std::map<std::string, std::string>& params,
                             UrlFetcher::Verb verb, GenericResponse* resp,
                             Task* task) {
  PurgeExpiredEntries();
  switch (verb) {
    case UrlFetcher::Verb::GET:
      HandleGet(key, params, resp, task);
      break;
    case UrlFetcher::Verb::POST:
      HandlePost(key, params, resp, task);
      break;
    case UrlFetcher::Verb::PUT:
      HandlePut(key, params, resp, task);
      break;
    case UrlFetcher::Verb::DELETE:
      HandleDelete(key, params, resp, task);
      break;
    default:
      LOG(FATAL) << "Unsupported verb " << static_cast<int>(verb);
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
                      const shared_ptr<JsonObject>& json) {
  JsonObject json_node;
  FillJsonForNode(node, &json_node);
  json->Add("action", action);
  json->Add("node", json_node);
}


void FillJsonForDir(const string& key, const vector<EtcdClient::Node>& nodes,
                    const string& action, const shared_ptr<JsonObject>& json) {
  JsonObject node;
  node.Add("modifiedIndex", 1);
  node.Add("createdIndex", 1);
  node.Add("key", key);
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
  unique_lock<mutex> lock(mutex_);
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (it->second.expires_ < system_clock::now()) {
      VLOG(1) << "Deleting expired entry " << it->first;
      it->second.deleted_ = true;
      NotifyForPath(lock, it->first);
      it = entries_.erase(it);
    } else {
      ++it;
    }
  }
}


void FakeEtcdClient::NotifyForPath(const unique_lock<mutex>& lock,
                                   const string& path) {
  CHECK(lock.owns_lock());
  VLOG(1) << "notifying " << path;
  const bool exists(entries_.find(path) != entries_.end());
  CHECK(exists);
  const Node& node(entries_.find(path)->second);
  for (const auto& pair : watches_) {
    if (path.find(pair.first) == 0) {
      for (const auto& cb_cookie : pair.second) {
        ScheduleWatchCallback(lock, cb_cookie.second,
                              bind(cb_cookie.first, vector<Node>{node}));
      }
    }
  }
}


void FakeEtcdClient::GetSingleEntry(const string& key, GenericResponse* resp,
                                    Task* task) {
  resp->etcd_index = index_;
  if (entries_.find(key) != entries_.end()) {
    const Node& node(entries_.find(key)->second);
    resp->json_body = make_shared<JsonObject>();
    FillJsonForEntry(node, "get", resp->json_body);
    task->Return();
  } else {
    resp->json_body = make_shared<JsonObject>();
    task->Return(Status(util::error::NOT_FOUND, "not found"));
  }
}


void FakeEtcdClient::GetDirectory(const string& key, GenericResponse* resp,
                                  Task* task) {
  VLOG(1) << "GET DIR";
  CHECK(key.back() == '/');
  vector<Node> nodes;
  for (const auto& pair : entries_) {
    if (pair.first.find(key) == 0) {
      nodes.push_back(pair.second);
    }
  }
  resp->etcd_index = index_;
  resp->json_body = make_shared<JsonObject>();
  FillJsonForDir(key, nodes, "get", resp->json_body);
  VLOG(1) << resp->json_body->ToString();
  task->Return();
}


void FakeEtcdClient::HandleGet(const string& key,
                               const map<string, string>& params,
                               GenericResponse* resp, Task* task) {
  VLOG(1) << "GET " << key;
  lock_guard<mutex> lock(mutex_);
  if (key.back() == '/') {
    return GetDirectory(key, resp, task);
  } else {
    return GetSingleEntry(key, resp, task);
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
                                GenericResponse* resp, Task* task) {
  VLOG(1) << "POST " << key;
  unique_lock<mutex> lock(mutex_);
  const string path(EnsureEndsWithSlash(key) + to_string(index_));
  CHECK(params.find("value") != params.end());
  const string& value(params.find("value")->second);
  Node node(index_, index_, path, false, value, {}, false);
  MaybeSetExpiry(params, &node);
  entries_[path] = node;

  resp->etcd_index = ++index_;
  resp->json_body = make_shared<JsonObject>();
  FillJsonForEntry(node, "create", resp->json_body);
  task->Return();
  NotifyForPath(lock, path);
}


void FakeEtcdClient::HandlePut(const string& key,
                               const map<string, string>& params,
                               GenericResponse* resp, Task* task) {
  VLOG(1) << "PUT " << key;
  unique_lock<mutex> lock(mutex_);
  CHECK(key.back() != '/');
  CHECK(params.find("value") != params.end());
  const string& value(params.find("value")->second);
  Node node(index_, index_, key, false, value, {}, false);
  MaybeSetExpiry(params, &node);
  Status status(CheckCompareFlags(params, key));
  if (!status.ok()) {
    resp->etcd_index = index_;
    resp->json_body = make_shared<JsonObject>();
    task->Return(status);
    return;
  }
  if (entries_.find(key) != entries_.end()) {
    VLOG(1) << "Keeping original created_index_";
    node.created_index_ = entries_.find(key)->second.created_index_;
  }

  entries_[key] = node;
  resp->etcd_index = ++index_;
  resp->json_body = make_shared<JsonObject>();
  FillJsonForEntry(node, "set", resp->json_body);
  task->Return();
  NotifyForPath(lock, key);
}


void FakeEtcdClient::HandleDelete(const string& key,
                                  const map<string, string>& params,
                                  GenericResponse* resp, Task* task) {
  VLOG(1) << "DELETE " << key;
  unique_lock<mutex> lock(mutex_);
  CHECK(key.back() != '/');
  Status status(CheckCompareFlags(params, key));
  if (!status.ok()) {
    resp->etcd_index = index_;
    resp->json_body = make_shared<JsonObject>();
    task->Return(status);
    return;
  }
  entries_[key].deleted_ = true;
  resp->etcd_index = ++index_;
  resp->json_body = make_shared<JsonObject>();
  FillJsonForEntry(entries_[key], "delete", resp->json_body);
  task->Return();
  NotifyForPath(lock, key);
  entries_.erase(key);
}


void FakeEtcdClient::CancelWatch(Task* task) {
  lock_guard<mutex> lock(mutex_);
  bool found(false);
  for (auto& pair : watches_) {
    for (auto it(pair.second.begin()); it != pair.second.end();) {
      if (it->second == task) {
        CHECK(!found);
        found = true;
        VLOG(1) << "Removing watcher " << it->second << " on " << pair.first;
        // Outstanding notifications have a hold on this task, so they
        // will all go through before the task actually completes. But
        // we won't be sending new notifications.
        task->Return(Status::CANCELLED);
        it = pair.second.erase(it);
      } else {
        ++it;
      }
    }
  }
}


void FakeEtcdClient::ScheduleWatchCallback(
    const unique_lock<mutex>& lock, Task* task,
    const std::function<void()>& callback) {
  CHECK(lock.owns_lock());
  const bool already_running(!watches_callbacks_.empty());

  task->AddHold();
  watches_callbacks_.emplace_back(make_pair(task, move(callback)));

  // TODO(pphaneuf): This might fare poorly if the executor is
  // synchronous.
  if (!already_running) {
    watches_callbacks_.front().first->executor()->Add(
        bind(&FakeEtcdClient::RunWatchCallback, this));
  }
}


void FakeEtcdClient::RunWatchCallback() {
  Task* current(nullptr);
  Task* next(nullptr);
  function<void()> callback;

  {
    lock_guard<mutex> lock(mutex_);

    CHECK(!watches_callbacks_.empty());
    current = move(watches_callbacks_.front().first);
    callback = move(watches_callbacks_.front().second);
    watches_callbacks_.pop_front();

    if (!watches_callbacks_.empty()) {
      next = CHECK_NOTNULL(watches_callbacks_.front().first);
    }
  }

  callback();
  current->RemoveHold();

  // If we have a next executor, schedule ourselves on it.
  if (next) {
    next->executor()->Add(bind(&FakeEtcdClient::RunWatchCallback, this));
  }
}


}  // namespace cert_trans
