#include "util/fake_etcd.h"

#include <atomic>
#include <functional>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "base/notification.h"
#include "util/libevent_wrapper.h"
#include "util/status_test_util.h"
#include "util/sync_task.h"
#include "util/testing.h"
#include "util/thread_pool.h"

namespace cert_trans {

using std::bind;
using std::chrono::seconds;
using std::deque;
using std::function;
using std::lock_guard;
using std::mutex;
using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;
using std::string;
using std::this_thread::sleep_for;
using std::unique_ptr;
using std::vector;
using testing::DoAll;
using testing::ElementsAre;
using testing::InvokeWithoutArgs;
using testing::Matches;
using testing::Mock;
using testing::MockFunction;
using testing::StrictMock;
using testing::TestInfo;
using testing::UnitTest;
using testing::_;
using util::Status;
using util::SyncTask;
using util::testing::StatusIs;

DEFINE_string(etcd, "", "etcd server address");
DEFINE_int32(etcd_port, 4001, "etcd server port");

const char kValue[] = "value";
const char kValue2[] = "value2";


class FakeEtcdTest : public ::testing::Test {
 public:
  FakeEtcdTest()
      : base_(std::make_shared<libevent::Base>()),
        event_pump_(base_),
        fetcher_(base_.get()),
        client_(FLAGS_etcd.empty()
                    ? new FakeEtcdClient
                    : new EtcdClient(&fetcher_, FLAGS_etcd, FLAGS_etcd_port)),
        key_prefix_(BuildKeyPrefix()) {
  }

 protected:
  Status BlockingGet(const string& key, EtcdClient::Node* node) {
    SyncTask task(base_.get());
    EtcdClient::GetResponse resp;
    client_->Get(key, &resp, task.task());
    task.Wait();
    *node = resp.node;
    return task.status();
  }

  Status BlockingCreate(const string& key, const string& value,
                        int64_t* created_index) {
    SyncTask task(base_.get());
    EtcdClient::Response resp;
    client_->Create(key, value, &resp, task.task());
    task.Wait();
    *created_index = resp.etcd_index;
    return task.status();
  }

  Status BlockingCreateWithTTL(const string& key, const string& value,
                               const seconds& ttl, int64_t* created_index) {
    SyncTask task(base_.get());
    EtcdClient::Response resp;
    client_->CreateWithTTL(key, value, ttl, &resp, task.task());
    task.Wait();
    *created_index = resp.etcd_index;
    return task.status();
  }

  Status BlockingUpdate(const string& key, const string& value,
                        int64_t old_index, int64_t* modified_index) {
    SyncTask task(base_.get());
    EtcdClient::Response resp;
    client_->Update(key, value, old_index, &resp, task.task());
    task.Wait();
    *modified_index = resp.etcd_index;
    return task.status();
  }

  Status BlockingUpdateWithTTL(const string& key, const string& value,
                               const seconds& ttl, int64_t previous_index,
                               int64_t* modified_index) {
    SyncTask task(base_.get());
    EtcdClient::Response resp;
    client_->UpdateWithTTL(key, value, ttl, previous_index, &resp,
                           task.task());
    task.Wait();
    *modified_index = resp.etcd_index;
    return task.status();
  }

  Status BlockingForceSet(const string& key, const string& value,
                          int64_t* modified_index) {
    SyncTask task(base_.get());
    EtcdClient::Response resp;
    client_->ForceSet(key, value, &resp, task.task());
    task.Wait();
    *modified_index = resp.etcd_index;
    return task.status();
  }

  Status BlockingForceSetWithTTL(const string& key, const string& value,
                                 const seconds& ttl, int64_t* modified_index) {
    SyncTask task(base_.get());
    EtcdClient::Response resp;
    client_->ForceSetWithTTL(key, value, ttl, &resp, task.task());
    task.Wait();
    *modified_index = resp.etcd_index;
    return task.status();
  }

  Status BlockingDelete(const string& key, int64_t previous_index) {
    SyncTask task(base_.get());
    client_->Delete(key, previous_index, task.task());
    task.Wait();
    return task.status();
  }

  static string BuildKeyPrefix() {
    const TestInfo* const test_info(
        UnitTest::GetInstance()->current_test_info());
    string retval("/testing/");
    retval.append(test_info->test_case_name());
    retval.append("/");
    retval.append(test_info->name());
    return retval;
  }

  std::shared_ptr<libevent::Base> base_;
  libevent::EventPumpThread event_pump_;
  UrlFetcher fetcher_;
  const unique_ptr<EtcdClient> client_;
  const string key_prefix_;
};


TEST_F(FakeEtcdTest, Create) {
  int64_t created_index;
  EXPECT_OK(BlockingCreate(key_prefix_, kValue, &created_index));

  EtcdClient::Node node;
  EXPECT_OK(BlockingGet(key_prefix_, &node));
  EXPECT_EQ(kValue, node.value_);
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(created_index, node.modified_index_);
}


TEST_F(FakeEtcdTest, CreateFailsIfExists) {
  int64_t created_index;
  EXPECT_OK(BlockingCreate(key_prefix_, kValue, &created_index));
  EXPECT_THAT(BlockingCreate(key_prefix_, kValue, &created_index),
              StatusIs(util::error::FAILED_PRECONDITION));
}


TEST_F(FakeEtcdTest, Update) {
  int64_t created_index;
  EXPECT_OK(BlockingCreate(key_prefix_, kValue, &created_index));

  int64_t modified_index;
  EXPECT_OK(
      BlockingUpdate(key_prefix_, kValue2, created_index, &modified_index));

  EtcdClient::Node node;
  EXPECT_OK(BlockingGet(key_prefix_, &node));
  EXPECT_EQ(kValue2, node.value_);
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(modified_index, node.modified_index_);
  EXPECT_LT(created_index, modified_index);
}


TEST_F(FakeEtcdTest, UpdateFailsWithIncorrectPreviousIndex) {
  int64_t created_index;
  EXPECT_OK(BlockingCreate(key_prefix_, kValue, &created_index));

  int64_t modified_index(-1);
  EXPECT_THAT(BlockingUpdate(key_prefix_, kValue2, created_index - 1,
                             &modified_index),
              StatusIs(util::error::FAILED_PRECONDITION));
  EXPECT_EQ(-1, modified_index);

  EtcdClient::Node node;
  EXPECT_OK(BlockingGet(key_prefix_, &node));
  EXPECT_EQ(kValue, node.value_);  // Not updated!
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(created_index, node.modified_index_);
}


TEST_F(FakeEtcdTest, CreateWithTTLExpires) {
  seconds kTtl(3);

  int64_t created_index;
  EXPECT_OK(BlockingCreateWithTTL(key_prefix_, kValue, kTtl, &created_index));

  EtcdClient::Node node;
  EXPECT_OK(BlockingGet(key_prefix_, &node));
  EXPECT_EQ(kValue, node.value_);
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(created_index, node.modified_index_);

  // Now wait for it to expire
  sleep_for(kTtl + seconds(1));

  // Vanished, in a puff of digital smoke:
  EXPECT_THAT(BlockingGet(key_prefix_, &node),
              StatusIs(util::error::NOT_FOUND));
}


TEST_F(FakeEtcdTest, UpdateWithTTLExpires) {
  seconds kTtl(3);

  int64_t created_index;
  EXPECT_OK(BlockingCreate(key_prefix_, kValue, &created_index));

  int64_t modified_index;
  EXPECT_OK(BlockingUpdateWithTTL(key_prefix_, kValue2, kTtl, created_index,
                                  &modified_index));
  EXPECT_LT(created_index, modified_index);

  EtcdClient::Node node;
  EXPECT_OK(BlockingGet(key_prefix_, &node));
  EXPECT_EQ(kValue2, node.value_);
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(modified_index, node.modified_index_);

  // Now wait for it to expire
  sleep_for(kTtl + seconds(1));

  // Vanished, in a puff of digital smoke:
  EXPECT_THAT(BlockingGet(key_prefix_, &node), StatusIs(util::error::NOT_FOUND));
}


TEST_F(FakeEtcdTest, ForceSet) {
  int64_t created_index;
  EXPECT_OK(BlockingCreate(key_prefix_, kValue, &created_index));

  int64_t modified_index;
  EXPECT_OK(BlockingForceSet(key_prefix_, kValue2, &modified_index));

  EtcdClient::Node node;
  EXPECT_OK(BlockingGet(key_prefix_, &node));
  EXPECT_EQ(kValue2, node.value_);
  EXPECT_EQ(modified_index, node.created_index_);
  EXPECT_EQ(modified_index, node.modified_index_);
  EXPECT_LT(created_index, modified_index);
}


TEST_F(FakeEtcdTest, ForceSetWithTTLExpires) {
  seconds kTtl(3);

  int64_t created_index;
  EXPECT_OK(BlockingCreate(key_prefix_, kValue, &created_index));

  int64_t modified_index;
  EXPECT_OK(BlockingForceSetWithTTL(key_prefix_, kValue2, kTtl,
                                    &modified_index));
  EXPECT_LT(created_index, modified_index);

  EtcdClient::Node node;
  EXPECT_OK(BlockingGet(key_prefix_, &node));
  EXPECT_EQ(kValue2, node.value_);
  EXPECT_EQ(modified_index, node.created_index_);
  EXPECT_EQ(modified_index, node.modified_index_);

  // Now wait for it to expire
  sleep_for(kTtl + seconds(1));

  // Vanished, in a puff of digital smoke:
  EXPECT_THAT(BlockingGet(key_prefix_, &node), StatusIs(util::error::NOT_FOUND));
}


TEST_F(FakeEtcdTest, DeleteNonExistent) {
  Status status(BlockingDelete("/potato", 42));
  EXPECT_EQ(util::error::NOT_FOUND, status.CanonicalCode()) << status;
}


TEST_F(FakeEtcdTest, DeleteIncorrectIndex) {
  int64_t created_index;
  EXPECT_OK(BlockingCreate(key_prefix_, kValue, &created_index));

  EtcdClient::Node node;
  EXPECT_OK(BlockingGet(key_prefix_, &node));
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(created_index, node.modified_index_);

  EXPECT_THAT(BlockingDelete(key_prefix_, created_index + 1),
              StatusIs(util::error::FAILED_PRECONDITION));

  EXPECT_OK(BlockingGet(key_prefix_, &node));
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(created_index, node.modified_index_);
}


TEST_F(FakeEtcdTest, Delete) {
  int64_t created_index;
  EXPECT_OK(BlockingCreate(key_prefix_, kValue, &created_index));

  EtcdClient::Node node;
  EXPECT_OK(BlockingGet(key_prefix_, &node));
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(created_index, node.modified_index_);

  EXPECT_OK(BlockingDelete(key_prefix_, created_index));

  EXPECT_THAT(BlockingGet(key_prefix_, &node),
              StatusIs(util::error::NOT_FOUND));
}


class CheckingExecutor : public util::Executor {
 public:
  CheckingExecutor() : inner_(1), in_executor_(false) {
  }

  void Add(const std::function<void()>& closure) override {
    inner_.Add(bind(&CheckingExecutor::Check, this, closure));
  }

  void CheckInExecutor() const {
    lock_guard<mutex> lock(lock_);
    EXPECT_TRUE(in_executor_);
  }

 private:
  void Check(const std::function<void()>& closure) {
    {
      lock_guard<mutex> lock(lock_);
      CHECK(!in_executor_);
      in_executor_ = true;
    }
    closure();
    {
      lock_guard<mutex> lock(lock_);
      CHECK(in_executor_);
      in_executor_ = false;
    }
  }

  ThreadPool inner_;
  mutable mutex lock_;
  bool in_executor_;
};


MATCHER_P3(EtcdClientNodeIs, key, value, deleted, "") {
  return Matches(key)(arg.key_) && Matches(value)(arg.value_) &&
         Matches(deleted)(arg.deleted_);
}


TEST_F(FakeEtcdTest, WatcherForExecutor) {
  const string kDir(key_prefix_);
  const string kPath1(kDir + "/1");
  const string kPath2(kDir + "/2");

  // Make sure the directory exists and has something in it before watching.
  int64_t bogus_index;
  ASSERT_OK(BlockingCreate(kPath1, "", &bogus_index));

  StrictMock<MockFunction<void(const vector<EtcdClient::Node>&)>> watcher;
  CheckingExecutor checking_executor;
  SyncTask task(&checking_executor);
  Notification initial;
  EXPECT_CALL(watcher, Call(ElementsAre(EtcdClientNodeIs(kPath1, "", false))))
      .WillOnce(DoAll(InvokeWithoutArgs(&initial, &Notification::Notify),
                      InvokeWithoutArgs(&checking_executor,
                                        &CheckingExecutor::CheckInExecutor)));

  client_->Watch(
      kDir, bind(&MockFunction<void(const vector<EtcdClient::Node>&)>::Call,
                 &watcher, _1),
      task.task());

  ASSERT_TRUE(initial.WaitForNotificationWithTimeout(seconds(1)));
  Mock::VerifyAndClearExpectations(&watcher);

  Notification second;
  EXPECT_CALL(watcher,
              Call(ElementsAre(EtcdClientNodeIs(kPath2, kValue, false))))
      .WillOnce(DoAll(InvokeWithoutArgs(&second, &Notification::Notify),
                      InvokeWithoutArgs(&checking_executor,
                                        &CheckingExecutor::CheckInExecutor)));

  int64_t created_index;
  EXPECT_OK(BlockingCreate(kPath2, kValue, &created_index));

  ASSERT_TRUE(second.WaitForNotificationWithTimeout(seconds(1)));

  task.Cancel();
  task.Wait();
  EXPECT_THAT(task.status(), StatusIs(util::error::CANCELLED));
}


TEST_F(FakeEtcdTest, WatcherForCreate) {
  const string kDir(key_prefix_);
  const string kPath1(kDir + "/1");
  const string kPath2(kDir + "/2");
  int64_t created_index;
  EXPECT_OK(BlockingCreate(kPath1, kValue, &created_index));

  StrictMock<MockFunction<void(const vector<EtcdClient::Node>&)>> watcher;
  Notification initial;
  EXPECT_CALL(watcher,
              Call(ElementsAre(EtcdClientNodeIs(kPath1, "value", false))))
      .WillOnce(InvokeWithoutArgs(&initial, &Notification::Notify));

  util::SyncTask watch_task(base_.get());
  client_->Watch(
      kDir, bind(&MockFunction<void(const vector<EtcdClient::Node>&)>::Call,
                 &watcher, _1),
      watch_task.task());

  ASSERT_TRUE(initial.WaitForNotificationWithTimeout(seconds(1)));
  Mock::VerifyAndClearExpectations(&watcher);

  Notification second;
  EXPECT_CALL(watcher,
              Call(ElementsAre(EtcdClientNodeIs(kPath2, kValue2, false))))
      .WillOnce(InvokeWithoutArgs(&second, &Notification::Notify));

  EXPECT_OK(BlockingCreate(kPath2, kValue2, &created_index));

  EXPECT_TRUE(initial.WaitForNotificationWithTimeout(seconds(1)));

  watch_task.Cancel();
  watch_task.Wait();
  EXPECT_THAT(watch_task.status(), StatusIs(util::error::CANCELLED));
}


TEST_F(FakeEtcdTest, WatcherForDelete) {
  const string kDir(key_prefix_);
  const string kPath(kDir + "/subkey");
  int64_t created_index;
  EXPECT_OK(BlockingCreate(kPath, kValue, &created_index));

  StrictMock<MockFunction<void(const vector<EtcdClient::Node>&)>> watcher;
  Notification initial;
  EXPECT_CALL(watcher,
              Call(ElementsAre(EtcdClientNodeIs(kPath, "value", false))))
      .WillOnce(InvokeWithoutArgs(&initial, &Notification::Notify));

  util::SyncTask watch_task(base_.get());
  client_->Watch(
      kDir, bind(&MockFunction<void(const vector<EtcdClient::Node>&)>::Call,
                 &watcher, _1),
      watch_task.task());

  ASSERT_TRUE(initial.WaitForNotificationWithTimeout(seconds(1)));
  Mock::VerifyAndClearExpectations(&watcher);

  Notification second;
  EXPECT_CALL(watcher, Call(ElementsAre(EtcdClientNodeIs(kPath, _, true))))
      .WillOnce(InvokeWithoutArgs(&second, &Notification::Notify));

  EXPECT_OK(BlockingDelete(kPath, created_index));

  EXPECT_TRUE(initial.WaitForNotificationWithTimeout(seconds(1)));

  watch_task.Cancel();
  watch_task.Wait();
  EXPECT_THAT(watch_task.status(), StatusIs(util::error::CANCELLED));
}


}  // namespace cert_trans


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
