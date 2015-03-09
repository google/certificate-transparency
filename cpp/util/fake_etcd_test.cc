#include "util/fake_etcd.h"

#include <atomic>
#include <functional>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "base/notification.h"
#include "util/libevent_wrapper.h"
#include "util/sync_task.h"
#include "util/testing.h"

namespace cert_trans {

using std::bind;
using std::chrono::duration;
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
using util::Status;
using util::SyncTask;

const char kKey[] = "/key";
const char kDir[] = "/dir/";
const char kPath1[] = "/dir/1";
const char kPath2[] = "/dir/2";
const char kValue[] = "value";
const char kValue2[] = "value2";


class FakeEtcdTest : public ::testing::Test {
 public:
  FakeEtcdTest()
      : base_(std::make_shared<libevent::Base>()),
        event_pump_(base_),
        client_(base_) {
  }

 protected:
  Status BlockingGet(const string& key, EtcdClient::Node* node) {
    SyncTask task(base_.get());
    EtcdClient::GetResponse resp;
    client_.Get(key, &resp, task.task());
    task.Wait();
    *node = resp.node;
    return task.status();
  }

  Status BlockingCreate(const string& key, const string& value,
                        int64_t* created_index) {
    SyncTask task(base_.get());
    EtcdClient::Response resp;
    client_.Create(key, value, &resp, task.task());
    task.Wait();
    *created_index = resp.etcd_index;
    return task.status();
  }

  Status BlockingCreateWithTTL(const string& key, const string& value,
                               const duration<int64_t>& ttl,
                               int64_t* created_index) {
    SyncTask task(base_.get());
    EtcdClient::Response resp;
    client_.CreateWithTTL(key, value, ttl, &resp, task.task());
    task.Wait();
    *created_index = resp.etcd_index;
    return task.status();
  }

  Status BlockingCreateInQueue(const string& dir, const string& value,
                               string* created_key, int64_t* created_index) {
    SyncTask task(base_.get());
    EtcdClient::CreateInQueueResponse resp;
    client_.CreateInQueue(dir, value, &resp, task.task());
    task.Wait();
    *created_index = resp.etcd_index;
    *created_key = resp.key;
    return task.status();
  }

  Status BlockingUpdate(const string& key, const string& value,
                        int64_t old_index, int64_t* modified_index) {
    SyncTask task(base_.get());
    EtcdClient::Response resp;
    client_.Update(key, value, old_index, &resp, task.task());
    task.Wait();
    *modified_index = resp.etcd_index;
    return task.status();
  }

  Status BlockingUpdateWithTTL(const string& key, const string& value,
                               const duration<int>& ttl,
                               int64_t previous_index,
                               int64_t* modified_index) {
    SyncTask task(base_.get());
    EtcdClient::Response resp;
    client_.UpdateWithTTL(key, value, ttl, previous_index, &resp, task.task());
    task.Wait();
    *modified_index = resp.etcd_index;
    return task.status();
  }

  Status BlockingForceSet(const string& key, const string& value,
                          int64_t* modified_index) {
    SyncTask task(base_.get());
    EtcdClient::Response resp;
    client_.ForceSet(key, value, &resp, task.task());
    task.Wait();
    *modified_index = resp.etcd_index;
    return task.status();
  }

  Status BlockingForceSetWithTTL(const string& key, const string& value,
                                 const duration<int>& ttl,
                                 int64_t* modified_index) {
    SyncTask task(base_.get());
    EtcdClient::Response resp;
    client_.ForceSetWithTTL(key, value, ttl, &resp, task.task());
    task.Wait();
    *modified_index = resp.etcd_index;
    return task.status();
  }

  Status BlockingDelete(const string& key, int64_t previous_index) {
    SyncTask task(base_.get());
    client_.Delete(key, previous_index, task.task());
    task.Wait();
    return task.status();
  }

  std::shared_ptr<libevent::Base> base_;
  libevent::EventPumpThread event_pump_;
  FakeEtcdClient client_;
};


TEST_F(FakeEtcdTest, TestCreate) {
  Status status;
  int64_t created_index;
  status = BlockingCreate(kKey, kValue, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  EtcdClient::Node node;
  status = BlockingGet(kKey, &node);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(kValue, node.value_);
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(created_index, node.modified_index_);
}


TEST_F(FakeEtcdTest, TestCreateFailsIfExists) {
  Status status;
  int64_t created_index;
  status = BlockingCreate(kKey, kValue, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  status = BlockingCreate(kKey, kValue, &created_index);
  EXPECT_EQ(util::error::FAILED_PRECONDITION, status.CanonicalCode())
      << status;
}


TEST_F(FakeEtcdTest, TestCreateInQueue) {
  Status status;
  int64_t created_index;
  string created_key;
  status = BlockingCreateInQueue(kDir, kValue, &created_key, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  EtcdClient::Node node;
  status = BlockingGet(created_key, &node);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(kValue, node.value_);
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(created_index, node.modified_index_);
}


TEST_F(FakeEtcdTest, TestUpdate) {
  Status status;
  int64_t created_index;
  status = BlockingCreate(kKey, kValue, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  int64_t modified_index;
  status = BlockingUpdate(kKey, kValue2, created_index, &modified_index);
  EXPECT_TRUE(status.ok()) << status;

  EtcdClient::Node node;
  status = BlockingGet(kKey, &node);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(kValue2, node.value_);
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(modified_index, node.modified_index_);
  EXPECT_LT(created_index, modified_index);
}


TEST_F(FakeEtcdTest, TestUpdateFailsWithIncorrectPreviousIndex) {
  Status status;
  int64_t created_index;
  status = BlockingCreate(kKey, kValue, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  int64_t modified_index(-1);
  status = BlockingUpdate(kKey, kValue2, created_index - 1, &modified_index);
  EXPECT_EQ(util::error::FAILED_PRECONDITION, status.CanonicalCode())
      << status;
  EXPECT_EQ(-1, modified_index);

  EtcdClient::Node node;
  status = BlockingGet(kKey, &node);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(kValue, node.value_);  // Not updated!
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(created_index, node.modified_index_);
}


TEST_F(FakeEtcdTest, TestCreateWithTTLExpires) {
  duration<int> kTtl(3);

  Status status;
  int64_t created_index;
  status = BlockingCreateWithTTL(kKey, kValue, kTtl, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  EtcdClient::Node node;
  status = BlockingGet(kKey, &node);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(kValue, node.value_);
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(created_index, node.modified_index_);

  // Now wait for it to expire
  sleep_for(kTtl + duration<int>(1));

  // Vanished, in a puff of digital smoke:
  status = BlockingGet(kKey, &node);
  EXPECT_EQ(util::error::NOT_FOUND, status.CanonicalCode()) << status;
}


TEST_F(FakeEtcdTest, TestUpdateWithTTLExpires) {
  duration<int> kTtl(3);

  Status status;
  int64_t created_index;
  status = BlockingCreate(kKey, kValue, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  int64_t modified_index;
  status = BlockingUpdateWithTTL(kKey, kValue2, kTtl, created_index,
                                 &modified_index);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_LT(created_index, modified_index);

  EtcdClient::Node node;
  status = BlockingGet(kKey, &node);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(kValue2, node.value_);
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(modified_index, node.modified_index_);

  // Now wait for it to expire
  sleep_for(kTtl + duration<int>(1));

  // Vanished, in a puff of digital smoke:
  status = BlockingGet(kKey, &node);
  EXPECT_EQ(util::error::NOT_FOUND, status.CanonicalCode()) << status;
}


TEST_F(FakeEtcdTest, TestForceSet) {
  Status status;
  int64_t created_index;
  status = BlockingCreate(kKey, kValue, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  int64_t modified_index;
  status = BlockingForceSet(kKey, kValue2, &modified_index);
  EXPECT_TRUE(status.ok()) << status;

  EtcdClient::Node node;
  status = BlockingGet(kKey, &node);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(kValue2, node.value_);
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(modified_index, node.modified_index_);
  EXPECT_LT(created_index, modified_index);
}


TEST_F(FakeEtcdTest, TestForceSetWithTTLExpires) {
  duration<int> kTtl(3);

  Status status;
  int64_t created_index;
  status = BlockingCreate(kKey, kValue, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  int64_t modified_index;
  status = BlockingForceSetWithTTL(kKey, kValue2, kTtl, &modified_index);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_LT(created_index, modified_index);

  EtcdClient::Node node;
  status = BlockingGet(kKey, &node);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(kValue2, node.value_);
  EXPECT_EQ(created_index, node.created_index_);
  EXPECT_EQ(modified_index, node.modified_index_);

  // Now wait for it to expire
  sleep_for(kTtl + duration<int>(1));

  // Vanished, in a puff of digital smoke:
  status = BlockingGet(kKey, &node);
  EXPECT_EQ(util::error::NOT_FOUND, status.CanonicalCode()) << status;
}


TEST_F(FakeEtcdTest, TestDelete) {
  Status status;
  int64_t created_index;
  status = BlockingCreate(kKey, kValue, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  status = BlockingDelete(kKey, created_index);
  EXPECT_TRUE(status.ok()) << status;

  EtcdClient::Node node;
  status = BlockingGet(kKey, &node);
  EXPECT_EQ(util::error::NOT_FOUND, status.CanonicalCode()) << status;
}


class CheckingExecutor : public util::Executor {
 public:
  CheckingExecutor(util::Executor* inner, const deque<Notification*>& expected) : inner_(CHECK_NOTNULL(inner)), expected_(expected) {
  }

  void Add(const std::function<void()>& closure) override {
    inner_->Add(bind(&CheckingExecutor::Check, this, closure));
  }

 private:
  void Check(const std::function<void()>& closure) {
    Notification* const notification(GetNext());
    if (notification) {
      EXPECT_FALSE(notification->HasBeenNotified());
      closure();
      EXPECT_TRUE(notification->HasBeenNotified());
    } else {
      closure();
    }
  }

  Notification* GetNext() {
    lock_guard<mutex> lock(lock_);
    Notification* const notification(expected_.front());
    expected_.pop_front();
    return notification;
  }

  util::Executor* const inner_;
  mutex lock_;
  deque<Notification*> expected_;
};


void TestWatcherForExecutor(Notification* notifier, bool* been_called,
                            const vector<EtcdClient::WatchUpdate>& updates) {
  if (*been_called) {
    notifier->Notify();
  }
  *been_called = true;
}


TEST_F(FakeEtcdTest, TestWatcherForExecutor) {
  ThreadPool pool(2);

  Notification watch;
  Notification done;

  // First time is the initial watch state, second time is the create
  // notification, then the cancellation callback, and finally the
  // done callback.
  CheckingExecutor checking_executor(&pool, {nullptr, &watch, nullptr, &done});
  util::Task task(bind(&Notification::Notify, &done), &checking_executor);
  bool been_called(false);
  client_.Watch(kDir, bind(&TestWatcherForExecutor, &watch, &been_called, _1),
                &task);

  int64_t created_index;
  EXPECT_EQ(util::Status::OK, BlockingCreate(kPath1, kValue, &created_index));

  // Should fall straight through:
  // TODO(pphaneuf): But it doesn't really? I tried changing it for
  // EXPECT_TRUE(notifier.HasBeenNotified()), but that fails
  // sometimes.
  watch.WaitForNotification();

  task.Cancel();
  done.WaitForNotification();
  EXPECT_EQ(Status::CANCELLED, task.status());
}


void TestWatcherForCreateCallback(
    Notification* notifier, const vector<EtcdClient::WatchUpdate>& updates) {
  static int num_calls(0);
  LOG(INFO) << "Update " << num_calls;
  if (num_calls == 0) {
    // initial call will all dir entries
    EXPECT_EQ(1, updates.size());
    EXPECT_EQ(false, updates[0].node_.deleted_);
    EXPECT_EQ(kPath1, updates[0].node_.key_);
    EXPECT_EQ(kValue, updates[0].node_.value_);
  } else {
    EXPECT_EQ(1, updates.size());
    EXPECT_EQ(false, updates[0].node_.deleted_);
    EXPECT_EQ(kPath2, updates[0].node_.key_);
    EXPECT_EQ(kValue2, updates[0].node_.value_);
    notifier->Notify();
  }
  ++num_calls;
}


TEST_F(FakeEtcdTest, TestWatcherForCreate) {
  ThreadPool pool(2);
  int64_t created_index;
  Status status(BlockingCreate(kPath1, kValue, &created_index));
  EXPECT_TRUE(status.ok()) << status;

  Notification watch;
  util::SyncTask watch_task(&pool);
  client_.Watch(kDir, bind(&TestWatcherForCreateCallback, &watch, _1),
                watch_task.task());

  status = BlockingCreate(kPath2, kValue2, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  // Should fall straight through:
  // TODO(pphaneuf): But it doesn't really? I tried changing it for
  // EXPECT_TRUE(notifier.HasBeenNotified()), but that fails
  // sometimes.
  watch.WaitForNotification();

  watch_task.Cancel();
  watch_task.Wait();
}


void TestWatcherForDeleteCallback(
    Notification* notifier, int* num_calls,
    const vector<EtcdClient::WatchUpdate>& updates) {
  static mutex mymutex;

  lock_guard<mutex> lock(mymutex);
  LOG(INFO) << "Delete " << num_calls;
  if (*num_calls == 0) {
    // initial call will all dir entries
    EXPECT_EQ(1, updates.size());
    EXPECT_EQ(false, updates[0].node_.deleted_);
    EXPECT_EQ(kPath1, updates[0].node_.key_);
    EXPECT_EQ(kValue, updates[0].node_.value_);
  } else {
    EXPECT_EQ(1, updates.size());
    EXPECT_EQ(true, updates[0].node_.deleted_);
    EXPECT_EQ(kPath1, updates[0].node_.key_);
    notifier->Notify();
  }
  ++(*num_calls);
}


TEST_F(FakeEtcdTest, TestWatcherForDelete) {
  ThreadPool pool(2);
  int64_t created_index;
  Status status(BlockingCreate(kPath1, kValue, &created_index));
  EXPECT_TRUE(status.ok()) << status;

  Notification watch;
  util::SyncTask watch_task(&pool);
  int num_calls(0);
  client_.Watch(kDir,
                bind(&TestWatcherForDeleteCallback, &watch, &num_calls, _1),
                watch_task.task());

  status = BlockingDelete(kPath1, created_index);
  EXPECT_TRUE(status.ok()) << status;

  // Should fall straight through:
  // TODO(pphaneuf): But it doesn't really? I tried changing it for
  // EXPECT_TRUE(watch.HasBeenNotified()), but that fails
  // sometimes.
  watch.WaitForNotification();

  watch_task.Cancel();
  watch_task.Wait();
}


}  // namespace cert_trans


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
