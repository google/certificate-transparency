#include "util/task.h"

#include <glog/logging.h>

using std::bind;
using std::function;
using std::lock_guard;
using std::mutex;
using std::ostream;
using std::unique_lock;
using std::vector;

namespace util {


Task::Task(const function<void(Task*)>& done_callback, Executor* executor)
    : done_callback_(done_callback),
      executor_(CHECK_NOTNULL(executor)),
      state_(ACTIVE),
      holds_(0) {
}


Task::~Task() {
  CHECK_EQ(state_, DONE);
}


Status Task::status() const {
  lock_guard<mutex> lock(lock_);
  CHECK_NE(state_, ACTIVE);
  return status_;
}


bool Task::Return(const Status& status) {
  unique_lock<mutex> lock(lock_);

  if (state_ != ACTIVE) {
    return false;
  }

  status_ = status;
  state_ = PREPARED;

  // Do not touch any members after this, as the task object might be
  // deleted by the time this method returns.
  TryDoneTransition(&lock);

  return true;
}


void Task::AddHold() {
  lock_guard<mutex> lock(lock_);
  CHECK_NE(state_, DONE);
  ++holds_;
}


void Task::RemoveHold() {
  unique_lock<mutex> lock(lock_);

  CHECK_GT(holds_, 0);
  CHECK_NE(state_, DONE);
  --holds_;

  // Do not touch any members after this, as the task object might be
  // deleted by the time this method returns.
  TryDoneTransition(&lock);
}


bool Task::IsActive() const {
  lock_guard<mutex> lock(lock_);
  return state_ == ACTIVE;
}


bool Task::IsDone() const {
  lock_guard<mutex> lock(lock_);
  return state_ == DONE;
}


// After calling this method, the task object might have become
// invalid, if the transition to DONE worked, as the done callback is
// allowed to delete it. So make sure not to use any more member
// variables after calling this.
//
// It will also release "*lock", if that transition succeeds.
void Task::TryDoneTransition(unique_lock<mutex>* lock) {
  CHECK(lock->owns_lock());
  CHECK_NE(state_, DONE);

  if (state_ != PREPARED || holds_ > 0) {
    return;
  }

  state_ = DONE;

  // Give up the lock, as the callback is allowed to delete us. We
  // also do not want to cause a deadlock, in the possibility that the
  // executor is synchronous.
  lock->unlock();

  // Once this is called, the task might get deleted.
  executor_->Add(bind(done_callback_, this));
}


}  // namespace util
