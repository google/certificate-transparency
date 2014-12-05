#include "util/fake_etcd.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>
#include <thread>

#include "util/blocking_callback.h"
#include "util/json_wrapper.h"
#include "util/sync_etcd.h"
#include "util/testing.h"

namespace cert_trans {

using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;
using std::string;
using std::vector;
using testing::AllOf;
using testing::Contains;
using testing::InvokeArgument;
using testing::Pair;
using testing::_;
using util::Status;

const char kKey[] = "/key";
const char kDir[] = "/dir/";
const char kPath1[] = "/dir/1";
const char kPath2[] = "/dir/2";
const char kValue[] = "value";
const char kValue2[] = "value2";


template <class A>
void CopyCallback1(const std::function<void(void)>& cb, A* out, const A& in) {
  *out = in;
  cb();
}


template <class A, class B>
void CopyCallback2(const std::function<void(void)>& cb, A* a_out, B* b_out,
                   const A& a_in, const B& b_in) {
  *a_out = a_in;
  *b_out = b_in;
  cb();
}


template <class A, class B, class C>
void CopyCallback3(const std::function<void(void)>& cb, A* a_out, B* b_out,
                   C* c_out, const A& a_in, const B& b_in, const C& c_in) {
  *a_out = a_in;
  *b_out = b_in;
  *c_out = c_in;
  cb();
}


class FakeEtcdTest : public ::testing::Test {
 public:
 protected:
  util::Status BlockingGet(const string& key, EtcdClient::Node* node) {
    BlockingCallback block;
    util::Status status;
    client_.Get(key, std::bind(&CopyCallback2<util::Status, EtcdClient::Node>,
                               block.Callback(), &status, node, _1, _2));
    block.Wait();
    return status;
  }


  util::Status BlockingCreate(const string& key, const string& value,
                              int64_t* created_index) {
    BlockingCallback block;
    util::Status status;
    client_.Create(key, value, std::bind(&CopyCallback2<util::Status, int64_t>,
                                         block.Callback(), &status,
                                         created_index, _1, _2));
    block.Wait();
    return status;
  }


  util::Status BlockingCreateWithTTL(const string& key, const string& value,
                                     const std::chrono::duration<int64_t>& ttl,
                                     int64_t* created_index) {
    BlockingCallback block;
    util::Status status;
    client_.CreateWithTTL(key, value, ttl,
                          std::bind(&CopyCallback2<util::Status, int64_t>,
                                    block.Callback(), &status, created_index,
                                    _1, _2));
    block.Wait();
    return status;
  }


  util::Status BlockingCreateInQueue(const string& dir, const string& value,
                                     string* created_key,
                                     int64_t* created_index) {
    BlockingCallback block;
    util::Status status;
    client_.CreateInQueue(
        dir, value, std::bind(&CopyCallback3<util::Status, string, int64_t>,
                              block.Callback(), &status, created_key,
                              created_index, _1, _2, _3));
    block.Wait();
    return status;
  }


  util::Status BlockingUpdate(const string& key, const string& value,
                              int64_t old_index, int64_t* modified_index) {
    BlockingCallback block;
    util::Status status;
    client_.Update(key, value, old_index,
                   std::bind(&CopyCallback2<util::Status, int64_t>,
                             block.Callback(), &status, modified_index, _1,
                             _2));
    block.Wait();
    return status;
  }


  util::Status BlockingUpdateWithTTL(const string& key, const string& value,
                                     const std::chrono::duration<int>& ttl,
                                     int64_t previous_index,
                                     int64_t* modified_index) {
    BlockingCallback block;
    util::Status status;
    client_.UpdateWithTTL(key, value, ttl, previous_index,
                          std::bind(&CopyCallback2<util::Status, int64_t>,
                                    block.Callback(), &status, modified_index,
                                    _1, _2));
    block.Wait();
    return status;
  }


  util::Status BlockingForceSet(const string& key, const string& value,
                                int64_t* modified_index) {
    BlockingCallback block;
    util::Status status;
    client_.ForceSet(key, value,
                     std::bind(&CopyCallback2<util::Status, int64_t>,
                               block.Callback(), &status, modified_index, _1,
                               _2));
    block.Wait();
    return status;
  }


  util::Status BlockingForceSetWithTTL(const string& key, const string& value,
                                       const std::chrono::duration<int>& ttl,
                                       int64_t* modified_index) {
    BlockingCallback block;
    util::Status status;
    client_.ForceSetWithTTL(key, value, ttl,
                            std::bind(&CopyCallback2<util::Status, int64_t>,
                                      block.Callback(), &status,
                                      modified_index, _1, _2));
    block.Wait();
    return status;
  }


  util::Status BlockingDelete(const string& key, int64_t previous_index) {
    BlockingCallback block;
    util::Status status;
    client_.Delete(key, previous_index,
                   std::bind(&CopyCallback1<util::Status>, block.Callback(),
                             &status, _1));
    block.Wait();
    return status;
  }


  FakeEtcdClient client_;
};


TEST_F(FakeEtcdTest, TestCreate) {
  util::Status status;
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
  util::Status status;
  int64_t created_index;
  status = BlockingCreate(kKey, kValue, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  status = BlockingCreate(kKey, kValue, &created_index);
  EXPECT_EQ(util::error::FAILED_PRECONDITION, status.CanonicalCode())
      << status;
}


TEST_F(FakeEtcdTest, TestCreateInQueue) {
  util::Status status;
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
  util::Status status;
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
  util::Status status;
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
  std::chrono::duration<int> kTtl(3);

  util::Status status;
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
  std::this_thread::sleep_for(kTtl + std::chrono::duration<int>(1));

  // Vanished, in a puff of digital smoke:
  status = BlockingGet(kKey, &node);
  EXPECT_EQ(util::error::NOT_FOUND, status.CanonicalCode()) << status;
}


TEST_F(FakeEtcdTest, TestUpdateWithTTLExpires) {
  std::chrono::duration<int> kTtl(3);

  util::Status status;
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
  std::this_thread::sleep_for(kTtl + std::chrono::duration<int>(1));

  // Vanished, in a puff of digital smoke:
  status = BlockingGet(kKey, &node);
  EXPECT_EQ(util::error::NOT_FOUND, status.CanonicalCode()) << status;
}


TEST_F(FakeEtcdTest, TestForceSet) {
  util::Status status;
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
  std::chrono::duration<int> kTtl(3);

  util::Status status;
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
  std::this_thread::sleep_for(kTtl + std::chrono::duration<int>(1));

  // Vanished, in a puff of digital smoke:
  status = BlockingGet(kKey, &node);
  EXPECT_EQ(util::error::NOT_FOUND, status.CanonicalCode()) << status;
}


TEST_F(FakeEtcdTest, TestDelete) {
  util::Status status;
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
    const std::function<void(void)>& cb,
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
  util::Status status(BlockingCreate(kPath1, kValue, &created_index));
  EXPECT_TRUE(status.ok()) << status;

  BlockingCallback block;
  std::unique_ptr<EtcdClient::Watcher> watcher(client_.CreateWatcher(
      kDir, std::bind(&TestWatcherForCreateCallback, block.Callback(), _1)));

  status = BlockingCreate(kPath2, kValue2, &created_index);
  EXPECT_TRUE(status.ok()) << status;

  // Should fall straight through:
  block.Wait();
}


void TestWatcherForDeleteCallback(
    const std::function<void(void)>& cb,
    const vector<EtcdClient::Watcher::Update>& updates) {
  static int num_calls(0);
  static std::mutex mutex;

  std::lock_guard<std::mutex> lock(mutex);
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
  util::Status status(BlockingCreate(kPath1, kValue, &created_index));
  EXPECT_TRUE(status.ok()) << status;

  BlockingCallback block;
  vector<EtcdClient::Watcher::Update> updates;
  std::unique_ptr<EtcdClient::Watcher> watcher(client_.CreateWatcher(
      kDir, std::bind(&TestWatcherForDeleteCallback, block.Callback(), _1)));

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
