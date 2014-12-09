#include <atomic>
#include <functional>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <thread>

#include "base/notification.h"
#include "util/executor.h"
#include "util/task.h"
#include "util/testing.h"
#include "util/thread_pool.h"

using cert_trans::Notification;
using cert_trans::ThreadPool;
using std::bind;
using std::placeholders::_1;
using std::unique_ptr;

namespace {


class InlineExecutor : public util::Executor {
  void Add(const std::function<void()>& closure) override {
    closure();
  }
};


template <class T>
class TaskTest : public ::testing::Test {};


typedef ::testing::Test TaskDeathTest;


template <class TestExecutor, bool sync_done>
class TaskTester {
 public:
  TaskTester()
      : executor_(new TestExecutor),
        task_(bind(&TaskTester::DoneCallback, this, _1), executor_.get()) {
    if (sync_done) {
      ContinueDone();
    }
  }

  ~TaskTester() {
    done_started_.WaitForNotification();
    if (!done_continue_.HasBeenNotified()) {
      done_continue_.Notify();
    }
    done_finished_.WaitForNotification();
  }

  util::Task* task() {
    return &task_;
  }

  void WaitForDoneToStart() {
    done_started_.WaitForNotification();
  }

  bool HasDoneStarted() {
    return done_started_.HasBeenNotified();
  }

  void ContinueDone() {
    if (!done_continue_.HasBeenNotified()) {
      done_continue_.Notify();
    }
  }

  void WaitForDoneToFinish() {
    done_finished_.WaitForNotification();
  }

 private:
  void DoneCallback(util::Task* task) {
    CHECK(!task->IsActive());
    CHECK(task->IsDone());
    done_started_.Notify();
    done_continue_.WaitForNotification();
    done_finished_.Notify();
  }

  const unique_ptr<TestExecutor> executor_;
  util::Task task_;
  Notification done_started_;
  Notification done_continue_;
  Notification done_finished_;

  DISALLOW_COPY_AND_ASSIGN(TaskTester);
};


typedef ::testing::Types<TaskTester<ThreadPool, false>,
                         TaskTester<InlineExecutor, true>> MyTypes;
TYPED_TEST_CASE(TaskTest, MyTypes);


void DoNothing(util::Task* task) {
}


TEST_F(TaskDeathTest, DestroyIncompleteTask) {
  InlineExecutor executor;

  EXPECT_DEATH(util::Task(DoNothing, &executor),
               "Check failed: state_ == DONE");

  LOG(INFO) << "calling Return";
}


template <class TypeParam>
void WaitForReturnCallback(TypeParam* s, Notification* notifier) {
  s->WaitForDoneToStart();
  EXPECT_FALSE(s->task()->IsActive());
  EXPECT_TRUE(s->task()->IsDone());
  EXPECT_EQ(util::Status::OK, s->task()->status());
  s->ContinueDone();
  notifier->Notify();
}


TYPED_TEST(TaskTest, StateChanges) {
  ThreadPool pool;
  TypeParam s;

  EXPECT_TRUE(s.task()->IsActive());
  EXPECT_FALSE(s.task()->IsDone());

  Notification notifier;
  pool.Add(bind(&WaitForReturnCallback<TypeParam>, &s, &notifier));
  EXPECT_TRUE(s.task()->Return());

  notifier.WaitForNotification();
}


TYPED_TEST(TaskTest, Return) {
  TypeParam s;
  util::Status status(util::error::INVALID_ARGUMENT, "expected status");

  EXPECT_TRUE(s.task()->Return(status));
  EXPECT_FALSE(s.task()->IsActive());

  s.WaitForDoneToStart();
  EXPECT_EQ(status, s.task()->status());
}


TYPED_TEST(TaskTest, HoldBlocksDone) {
  TypeParam s;
  EXPECT_TRUE(s.task()->IsActive());
  EXPECT_FALSE(s.task()->IsDone());

  s.task()->AddHold();
  EXPECT_TRUE(s.task()->IsActive());
  EXPECT_FALSE(s.task()->IsDone());

  s.task()->Return();
  EXPECT_FALSE(s.task()->IsActive());
  EXPECT_FALSE(s.task()->IsDone());

  s.task()->RemoveHold();
  EXPECT_FALSE(s.task()->IsActive());
  EXPECT_TRUE(s.task()->IsDone());
}


TYPED_TEST(TaskTest, MultipleReturn) {
  TypeParam s;
  util::Status status1(util::error::INVALID_ARGUMENT, "expected status");
  util::Status status2(util::error::DEADLINE_EXCEEDED, "unexpected status");
  EXPECT_NE(status1, status2);

  EXPECT_TRUE(s.task()->Return(status1));
  EXPECT_FALSE(s.task()->Return(status2));
  EXPECT_FALSE(s.task()->IsActive());

  s.WaitForDoneToStart();
  EXPECT_EQ(status1, s.task()->status());
}


}  // namespace


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
