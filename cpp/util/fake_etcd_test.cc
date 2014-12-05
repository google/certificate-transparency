#include "util/fake_etcd.h"

#include <functional>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "util/blocking_callback.h"
#include "util/sync_etcd.h"
#include "util/testing.h"

namespace cert_trans {

using std::bind;
using std::chrono::duration;
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

const char kKey[] = "/key";
const char kDir[] = "/dir/";
const char kPath1[] = "/dir/1";
const char kPath2[] = "/dir/2";
const char kValue[] = "value";
const char kValue2[] = "value2";


template <class A>
void CopyCallback1(const function<void(void)>& cb, A* out, const A& in) {
  *out = in;
  cb();
}


template <class A, class B>
void CopyCallback2(const function<void(void)>& cb, A* a_out, B* b_out,
                   const A& a_in, const B& b_in) {
  *a_out = a_in;
  *b_out = b_in;
  cb();
}


template <class A, class B, class C>
void CopyCallback3(const function<void(void)>& cb, A* a_out, B* b_out,
                   C* c_out, const A& a_in, const B& b_in, const C& c_in) {
  *a_out = a_in;
  *b_out = b_in;
  *c_out = c_in;
  cb();
}


class FakeEtcdTest : public ::testing::Test {
 public:
 protected:
  Status BlockingGet(const string& key, EtcdClient::Node* node) {
    BlockingCallback block;
    Status status;
    client_.Get(key, bind(&CopyCallback2<Status, EtcdClient::Node>,
                          block.Callback(), &status, node, _1, _2));
    block.Wait();
    return status;
  }

  Status BlockingCreate(const string& key, const string& value,
                        int64_t* created_index) {
    BlockingCallback block;
    Status status;
    client_.Create(key, value,
                   bind(&CopyCallback2<Status, int64_t>, block.Callback(),
                        &status, created_index, _1, _2));
    block.Wait();
    return status;
  }

  Status BlockingCreateWithTTL(const string& key, const string& value,
                               const duration<int64_t>& ttl,
                               int64_t* created_index) {
    BlockingCallback block;
    Status status;
    client_.CreateWithTTL(key, value, ttl,
                          bind(&CopyCallback2<Status, int64_t>,
                               block.Callback(), &status, created_index, _1,
                               _2));
    block.Wait();
    return status;
  }

  Status BlockingCreateInQueue(const string& dir, const string& value,
                               string* created_key, int64_t* created_index) {
    BlockingCallback block;
    Status status;
    client_.CreateInQueue(dir, value,
                          bind(&CopyCallback3<Status, string, int64_t>,
                               block.Callback(), &status, created_key,
                               created_index, _1, _2, _3));
    block.Wait();
    return status;
  }

  Status BlockingUpdate(const string& key, const string& value,
                        int64_t old_index, int64_t* modified_index) {
    BlockingCallback block;
    Status status;
    client_.Update(key, value, old_index,
                   bind(&CopyCallback2<Status, int64_t>, block.Callback(),
                        &status, modified_index, _1, _2));
    block.Wait();
    return status;
  }

  Status BlockingUpdateWithTTL(const string& key, const string& value,
                               const duration<int>& ttl,
                               int64_t previous_index,
                               int64_t* modified_index) {
    BlockingCallback block;
    Status status;
    client_.UpdateWithTTL(key, value, ttl, previous_index,
                          bind(&CopyCallback2<Status, int64_t>,
                               block.Callback(), &status, modified_index, _1,
                               _2));
    block.Wait();
    return status;
  }

  Status BlockingForceSet(const string& key, const string& value,
                          int64_t* modified_index) {
    BlockingCallback block;
    Status status;
    client_.ForceSet(key, value,
                     bind(&CopyCallback2<Status, int64_t>, block.Callback(),
                          &status, modified_index, _1, _2));
    block.Wait();
    return status;
  }

  Status BlockingForceSetWithTTL(const string& key, const string& value,
                                 const duration<int>& ttl,
                                 int64_t* modified_index) {
    BlockingCallback block;
    Status status;
    client_.ForceSetWithTTL(key, value, ttl,
                            bind(&CopyCallback2<Status, int64_t>,
                                 block.Callback(), &status, modified_index, _1,
                                 _2));
    block.Wait();
    return status;
  }

  Status BlockingDelete(const string& key, int64_t previous_index) {
    BlockingCallback block;
    Status status;
    client_.Delete(key, previous_index, bind(&CopyCallback1<Status>,
                                             block.Callback(), &status, _1));
    block.Wait();
    return status;
  }

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


TEST_F(FakeEtcdTest, TestCreateWithTTLExires) {
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


void TestWatcherForCreateCallback(
    const function<void(void)>& cb,
    const vector<EtcdClient::Watcher::Update>& updates) {
  static int num_calls(0);
  LOG(INFO) << "Update " << num_calls;
  if (num_calls == 0) {
    // initial call will all dir entries
    EXPECT_EQ(1, updates.size());
    EXPECT_EQ(true, updates[0].exists_);
    EXPECT_EQ(kPath1, updates[0].node_.key_);
    EXPECT_EQ(kValue, updates[0].node_.value_);
  } else {
    EXPECT_EQ(1, updates.size());
    EXPECT_EQ(true, updates[0].exists_);
    EXPECT_EQ(kPath2, updates[0].node_.key_);
    EXPECT_EQ(kValue2, updates[0].node_.value_);
    cb();
  }
  ++num_calls;
}


TEST_F(FakeEtcdTest, TestWatcherForCreate) {
  int64_t created_index;
  Status status(BlockingCreate(kPath1, kValue, &created_index));
  EXPECT_TRUE(status.ok()) << status;

  BlockingCallback block;
  unique_ptr<EtcdClient::Watcher> watcher(client_.CreateWatcher(
      kDir, bind(&TestWatcherForCreateCallback, block.Callback(), _1)));

  status = BlockingCreate(kPath2, kValue2, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  // Should fall straight through:
  block.Wait();
}


void TestWatcherForDeleteCallback(
    const function<void(void)>& cb,
    const vector<EtcdClient::Watcher::Update>& updates) {
  static int num_calls(0);
  static mutex mymutex;

  lock_guard<mutex> lock(mymutex);
  LOG(INFO) << "Delete " << num_calls;
  if (num_calls == 0) {
    // initial call will all dir entries
    EXPECT_EQ(1, updates.size());
    EXPECT_EQ(true, updates[0].exists_);
    EXPECT_EQ(kPath1, updates[0].node_.key_);
    EXPECT_EQ(kValue, updates[0].node_.value_);
  } else {
    EXPECT_EQ(1, updates.size());
    EXPECT_EQ(false, updates[0].exists_);
    EXPECT_EQ(kPath1, updates[0].node_.key_);
    cb();
  }
  ++num_calls;
}


TEST_F(FakeEtcdTest, TestWatcherForDelete) {
  int64_t created_index;
  Status status(BlockingCreate(kPath1, kValue, &created_index));
  EXPECT_TRUE(status.ok()) << status;

  BlockingCallback block;
  vector<EtcdClient::Watcher::Update> updates;
  unique_ptr<EtcdClient::Watcher> watcher(client_.CreateWatcher(
      kDir, bind(&TestWatcherForDeleteCallback, block.Callback(), _1)));

  status = BlockingDelete(kPath1, created_index);
  EXPECT_TRUE(status.ok()) << status;

  // Should fall straight through:
  block.Wait();
}


}  // namespace cert_trans


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
