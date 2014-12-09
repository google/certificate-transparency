// This class is used to coordinate asynchronous work. It runs a
// callback once the work is done.
//
// Typically, a function/method that starts an asynchronous operation
// will take a pointer to a util::Task. The caller keeps ownership of
// the util::Task, and once the operation is complete, the callee
// calls util::Task::Return(), with the status in case of an
// error.
//
// A task is provided with a util::Executor which it will use to run
// its callback. The executor will not be accessed after the done
// callback has started.
//
// Once util::Task::Return() is called, the done callback is run on
// the executor.

#ifndef CERT_TRANS_UTIL_TASK_H_
#define CERT_TRANS_UTIL_TASK_H_

#include <memory>
#include <mutex>
#include <vector>

#include "base/macros.h"
#include "util/executor.h"
#include "util/status.h"

namespace util {

// The task can be in one of three states: ACTIVE (the initial state),
// PREPARED (the task has a status), or DONE (the done callback can
// run).
//
// A task enters the PREPARED state on the first Return() call.
//
// The task changes from PREPARED to DONE when the following condition
// is met:
//
//  - there are no remaining holds on the task
//
class Task {
 public:
  Task(const std::function<void(Task*)>& done_callback, Executor* executor);

  // REQUIRES: task is in DONE state.
  // Tasks can be deleted in their done callback.
  ~Task();

  // REQUIRES: Return() has been called, which can be verified by
  // calling IsActive().
  Status status() const;

  // Methods used by the implementer of an asynchronous operation (the
  // callee).

  // If the task is ACTIVE, prepares it with the specified Status
  // object, returning true. If the task is no longer ACTIVE (meaning
  // that Return() has already been called), the task is not changed,
  // and false is returned.
  //
  // Note that once Return() is called, the task can reach the DONE
  // state asynchronously and run the callback for this task, which
  // might delete the task and state used by the callee. So you must
  // be careful with what is used after calling Return(), including
  // through destructors of locally scoped objects (such as
  // std::lock_guard, for example). An option is to use a TaskHold to
  // ensure the task does not reach the DONE state prematurely.
  bool Return(const Status& status = Status::OK);

  // This can be used to prevent the task from advancing to the DONE
  // state.
  void AddHold();
  void RemoveHold();

  // These two methods allow inspecting the current state of the task.
  bool IsActive() const;
  bool IsDone() const;

 private:
  enum State {
    ACTIVE = 0,
    PREPARED = 1,
    DONE = 2,
  };

  void TryDoneTransition(std::unique_lock<std::mutex>* lock);

  const std::function<void(Task*)> done_callback_;
  Executor* const executor_;

  mutable std::mutex lock_;
  State state_;
  Status status_;  // not protected by lock_
  int holds_;

  DISALLOW_COPY_AND_ASSIGN(Task);
};


// Helper class, that adds a hold on a task, and automatically removes
// it when it goes out of scope.
class TaskHold {
 public:
  TaskHold(Task* task) : task_(task) {
    task_->AddHold();
  }
  ~TaskHold() {
    task_->RemoveHold();
  }

 private:
  Task* const task_;

  DISALLOW_COPY_AND_ASSIGN(TaskHold);
};


}  // namespace util

#endif  // CERT_TRANS_UTIL_Task_H_
