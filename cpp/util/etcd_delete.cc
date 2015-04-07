#include "util/etcd_delete.h"

#include <functional>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <mutex>

using std::move;
using std::mutex;
using std::pair;
using std::placeholders::_1;
using std::string;
using std::unique_lock;
using std::vector;
using util::Status;
using util::Task;
using util::TaskHold;

DEFINE_int32(etcd_delete_concurrency, 4,
             "number of etcd keys to delete at a time");

namespace cert_trans {

namespace {


class DeleteState {
 public:
  DeleteState(EtcdClient* client, vector<pair<string, int64_t>>&& keys,
              Task* task)
      : client_(CHECK_NOTNULL(client)),
        task_(CHECK_NOTNULL(task)),
        outstanding_(0),
        keys_(move(keys)),
        it_(keys_.begin()) {
    CHECK_GT(FLAGS_etcd_delete_concurrency, 0);

    if (it_ == keys_.end()) {
      // Nothing to do!
      task_->Return();
    } else {
      StartNextRequest(unique_lock<mutex>(mutex_));
    }
  }

  ~DeleteState() {
    CHECK_EQ(outstanding_, 0);
  }

 private:
  void RequestDone(Task* child_task);
  void StartNextRequest(unique_lock<mutex>&& lock);

  EtcdClient* const client_;
  Task* const task_;
  mutex mutex_;
  int outstanding_;
  const vector<pair<string, int64_t>> keys_;
  vector<pair<string, int64_t>>::const_iterator it_;
};


void DeleteState::RequestDone(Task* child_task) {
  // If a child task has an error, return that error, and do not start
  // any more requests.
  if (!child_task->status().ok()) {
    task_->Return(child_task->status());
    return;
  }

  unique_lock<mutex> lock(mutex_);
  --outstanding_;

  if (it_ != keys_.end()) {
    StartNextRequest(move(lock));
  } else {
    if (outstanding_ < 1) {
      // No more keys to get, and this was the last one to complete.
      lock.unlock();
      task_->Return();
    }
  }
}


void DeleteState::StartNextRequest(unique_lock<mutex>&& lock) {
  CHECK(lock.owns_lock());

  if (task_->CancelRequested()) {
    // In case the task uses an inline executor.
    lock.unlock();
    task_->Return(Status::CANCELLED);
    return;
  }

  while (outstanding_ < FLAGS_etcd_delete_concurrency && it_ != keys_.end()) {
    CHECK(lock.owns_lock());
    const pair<string, int64_t>& key(*it_);
    ++it_;
    ++outstanding_;

    // In case the task uses an inline executor.
    lock.unlock();

    client_->Delete(key.first, key.second,
                    task_->AddChild(
                        bind(&DeleteState::RequestDone, this, _1)));

    // We must be holding the lock to evaluate the loop condition.
    lock.lock();
  }
}


}  // namespace


void EtcdDeleteKeys(EtcdClient* client, vector<pair<string, int64_t>>&& keys,
                    Task* task) {
  TaskHold hold(task);
  DeleteState* const state(new DeleteState(client, move(keys), task));
  task->DeleteWhenDone(state);
}


}  // namespace cert_trans
