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
using util::StatusOr;
using util::Task;

namespace cert_trans {
namespace {


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


}  // namespace


FakeEtcdClient::FakeEtcdClient() : index_(1) {
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
    case UrlFetcher::Verb::PUT:
      HandlePut(key, params, resp, task);
      break;
    case UrlFetcher::Verb::GET:
    case UrlFetcher::Verb::POST:
    case UrlFetcher::Verb::DELETE:
    default:
      LOG(FATAL) << "Unsupported verb " << static_cast<int>(verb);
  }
  DumpEntries();
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


void FakeEtcdClient::Get(const Request& req, GetResponse* resp, Task* task) {
  VLOG(1) << "GET " << req.key;
  CHECK(!req.key.empty());
  CHECK_EQ(req.key.front(), '/');
  CHECK(!req.recursive) << "not implemented";
  CHECK_LE(req.wait_index, 0) << "not implemented";

  PurgeExpiredEntries();
  lock_guard<mutex> lock(mutex_);
  resp->etcd_index = index_;
  if (req.key.back() == '/') {
    vector<Node> nodes;
    for (const auto& pair : entries_) {
      if (pair.first.find(req.key) == 0) {
        nodes.push_back(pair.second);
      }
    }
    resp->node = Node(1, 1, req.key, true, "", move(nodes), false);
  } else {
    const map<string, Node>::const_iterator it(entries_.find(req.key));
    if (it == entries_.end()) {
      task->Return(Status(util::error::NOT_FOUND, "not found"));
      return;
    }
    resp->node = it->second;
  }

  task->Return();
}


StatusOr<bool> FakeEtcdClient::CheckCompareFlags(
    const map<string, string> params, const string& key) {
  bool new_node(true);
  const bool entry_exists(entries_.find(key) != entries_.end());
  string prev_exist_str;
  if (GetParam(params, "prevExist", &prev_exist_str)) {
    const bool prev_exist(prev_exist_str == "true");
    if (entry_exists && !prev_exist) {
      return Status(util::error::FAILED_PRECONDITION, key + " Already exists");
    } else if (!entry_exists && prev_exist) {
      return Status(util::error::FAILED_PRECONDITION, key + " Not found");
    }
    new_node = false;
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
    new_node = false;
  }
  return new_node;
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
  StatusOr<bool> new_node(CheckCompareFlags(params, key));
  if (!new_node.status().ok()) {
    resp->etcd_index = index_;
    resp->json_body = make_shared<JsonObject>();
    task->Return(new_node.status());
    return;
  }
  if (!new_node.ValueOrDie() && entries_.find(key) != entries_.end()) {
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


void FakeEtcdClient::Delete(const string& key, const int64_t current_index,
                            Task* task) {
  VLOG(1) << "DELETE " << key;
  CHECK(!key.empty());
  CHECK_EQ(key.front(), '/');
  CHECK_NE(key.back(), '/');

  PurgeExpiredEntries();
  unique_lock<mutex> lock(mutex_);
  const map<string, Node>::iterator entry(entries_.find(key));
  if (entry == entries_.end()) {
    task->Return(Status(util::error::NOT_FOUND, "Node doesn't exist: " + key));
    return;
  }
  if (entry->second.modified_index_ != current_index) {
    task->Return(Status(util::error::FAILED_PRECONDITION,
                        "Incorrect index:  prevIndex=" +
                            to_string(current_index) +
                            " but modified_index_=" +
                            to_string(entry->second.modified_index_)));
    return;
  }
  entry->second.deleted_ = true;
  ++index_;
  task->Return();
  NotifyForPath(lock, key);
  entries_.erase(entry);
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
