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


FakeEtcdClient::FakeEtcdClient(libevent::Base* base)
    : base_(CHECK_NOTNULL(base)), parent_task_(base_), index_(1) {
}


FakeEtcdClient::~FakeEtcdClient() {
  parent_task_.task()->Return();
  parent_task_.Wait();
  CHECK_EQ(parent_task_.status(), Status::OK);
}


void FakeEtcdClient::DumpEntries(const unique_lock<mutex>& lock) const {
  CHECK(lock.owns_lock());
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
  ++stats_["watchers"];
}


void FakeEtcdClient::PurgeExpiredEntriesWithLock(
    const unique_lock<mutex>& lock) {
  CHECK(lock.owns_lock());
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (it->second.expires_ < system_clock::now()) {
      VLOG(1) << "Deleting expired entry " << it->first;
      it->second.deleted_ = true;
      NotifyForPath(lock, it->first);
      it = entries_.erase(it);
      ++stats_["expireCount"];
    } else {
      ++it;
    }
  }
}


void FakeEtcdClient::PurgeExpiredEntries() {
  unique_lock<mutex> lock(mutex_);
  PurgeExpiredEntriesWithLock(lock);
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

  unique_lock<mutex> lock(mutex_);
  PurgeExpiredEntriesWithLock(lock);
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
      ++stats_["getsFail"];
      return;
    }
    resp->node = it->second;
  }
  ++stats_["getsSuccess"];
  task->Return();
}


void FakeEtcdClient::InternalPut(const string& key, const string& value,
                                 const system_clock::time_point& expires,
                                 bool create, int64_t prev_index,
                                 Response* resp, Task* task) {
  CHECK_GT(key.size(), 0);
  CHECK_EQ(key.front(), '/');
  CHECK_NE(key.back(), '/');
  CHECK(!create || prev_index <= 0);

  *resp = EtcdClient::Response();
  unique_lock<mutex> lock(mutex_);
  PurgeExpiredEntriesWithLock(lock);
  const int64_t new_index(index_ + 1);
  Node node(new_index, new_index, key, false, value, {}, false);
  node.expires_ = expires;
  const map<string, Node>::const_iterator entry(entries_.find(key));
  if (create && entry != entries_.end()) {
    task->Return(
        Status(util::error::FAILED_PRECONDITION, key + " already exists"));
    return;
  }

  if (prev_index > 0) {
    if (entry == entries_.end()) {
      task->Return(Status(util::error::FAILED_PRECONDITION,
                          "node doesn't exist: " + key));
      return;
    }
    if (prev_index != entry->second.modified_index_) {
      task->Return(Status(util::error::FAILED_PRECONDITION,
                          "incorrect index:  prevIndex=" +
                              to_string(prev_index) + " but modified_index_=" +
                              to_string(entry->second.modified_index_)));
      return;
    }
    node.created_index_ = entry->second.created_index_;
  }

  entries_[key] = node;
  resp->etcd_index = new_index;
  index_ = new_index;
  task->Return();
  NotifyForPath(lock, key);
  DumpEntries(lock);
  if (expires < system_clock::time_point::max()) {
    const std::chrono::duration<double> delay(expires - system_clock::now());
    base_->Delay(delay, parent_task_.task()->AddChild(
                            bind(&FakeEtcdClient::PurgeExpiredEntries, this)));
  }
}


void FakeEtcdClient::UpdateOperationStats(const string& op, const Task* task) {
  CHECK_NOTNULL(task);
  if (!task->IsActive()) {
    std::lock_guard<std::mutex> lock(mutex_);
    ++stats_[op + (task->status().ok() ? "Success" : "Fail")];
  }
}


void FakeEtcdClient::Create(const string& key, const string& value,
                            Response* resp, Task* task) {
  task->CleanupWhenDone(
      bind(&FakeEtcdClient::UpdateOperationStats, this, "create", task));
  InternalPut(key, value, system_clock::time_point::max(), true, -1, resp,
              task);
}


void FakeEtcdClient::CreateWithTTL(const string& key, const string& value,
                                   const seconds& ttl, Response* resp,
                                   Task* task) {
  task->CleanupWhenDone(
      bind(&FakeEtcdClient::UpdateOperationStats, this, "create", task));
  InternalPut(key, value, system_clock::now() + ttl, true, -1, resp, task);
}


void FakeEtcdClient::Update(const string& key, const string& value,
                            const int64_t previous_index, Response* resp,
                            Task* task) {
  task->CleanupWhenDone(bind(&FakeEtcdClient::UpdateOperationStats, this,
                             "compareAndSwap", task));
  InternalPut(key, value, system_clock::time_point::max(), false,
              previous_index, resp, task);
}


void FakeEtcdClient::UpdateWithTTL(const string& key, const string& value,
                                   const seconds& ttl,
                                   const int64_t previous_index,
                                   Response* resp, Task* task) {
  task->CleanupWhenDone(bind(&FakeEtcdClient::UpdateOperationStats, this,
                             "compareAndSwap", task));
  InternalPut(key, value, system_clock::now() + ttl, false, previous_index,
              resp, task);
}


void FakeEtcdClient::ForceSet(const string& key, const string& value,
                              Response* resp, Task* task) {
  task->CleanupWhenDone(
      bind(&FakeEtcdClient::UpdateOperationStats, this, "set", task));
  InternalPut(key, value, system_clock::time_point::max(), false, -1, resp,
              task);
}


void FakeEtcdClient::ForceSetWithTTL(const std::string& key,
                                     const std::string& value,
                                     const std::chrono::seconds& ttl,
                                     Response* resp, util::Task* task) {
  task->CleanupWhenDone(
      bind(&FakeEtcdClient::UpdateOperationStats, this, "set", task));
  InternalPut(key, value, system_clock::now() + ttl, false, -1, resp, task);
}


void FakeEtcdClient::Delete(const string& key, const int64_t current_index,
                            Task* task) {
  VLOG(1) << "DELETE " << key;
  CHECK(!key.empty());
  CHECK_EQ(key.front(), '/');
  CHECK_NE(key.back(), '/');

  unique_lock<mutex> lock(mutex_);
  PurgeExpiredEntriesWithLock(lock);
  const map<string, Node>::iterator entry(entries_.find(key));
  if (entry == entries_.end()) {
    ++stats_["compareAndDeleteFail"];
    task->Return(Status(util::error::NOT_FOUND, "Node doesn't exist: " + key));
    return;
  }
  if (entry->second.modified_index_ != current_index) {
    ++stats_["compareAndDeleteFail"];
    task->Return(Status(util::error::FAILED_PRECONDITION,
                        "Incorrect index:  prevIndex=" +
                            to_string(current_index) +
                            " but modified_index_=" +
                            to_string(entry->second.modified_index_)));
    return;
  }
  entry->second.deleted_ = true;
  ++index_;
  ++stats_["compareAndDeleteSuccess"];
  task->Return();
  NotifyForPath(lock, key);
  entries_.erase(entry);
}


void FakeEtcdClient::GetStoreStats(StatsResponse* resp, Task* task) {
  CHECK_NOTNULL(resp);
  CHECK_NOTNULL(task);
  ++stats_["getsSuccess"];
  resp->stats = stats_;
  task->Return();
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
        --stats_["watchers"];
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
