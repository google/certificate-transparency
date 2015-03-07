#include "util/etcd.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>

#include "base/notification.h"
#include "util/json_wrapper.h"
#include "util/sync_task.h"
#include "util/testing.h"

namespace cert_trans {

using std::bind;
using std::chrono::seconds;
using std::make_pair;
using std::make_shared;
using std::map;
using std::pair;
using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;
using std::placeholders::_4;
using std::placeholders::_5;
using std::shared_ptr;
using std::string;
using std::vector;
using testing::AllOf;
using testing::Contains;
using testing::ElementsAre;
using testing::Field;
using testing::Invoke;
using testing::Pair;
using testing::StrictMock;
using testing::_;
using util::Status;
using util::SyncTask;
using util::Task;

namespace {

const char kEntryKey[] = "/some/key";
const char kDirKey[] = "/some";
const char kValueParam[] = "value";
const char kPrevExistParam[] = "prevExist";
const char kPrevIndexParam[] = "prevIndex";
const char kTtlParam[] = "ttl";
const char kFalse[] = "false";
const char kGetJson[] =
    "{"
    "  \"action\": \"get\","
    "  \"node\": {"
    "    \"createdIndex\": 6,"
    "    \"key\": \"/some/key\","
    "    \"modifiedIndex\": 9,"
    "    \"value\": \"123\""
    "  }"
    "}";

const char kGetAllJson[] =
    "{"
    "  \"action\": \"get\","
    "  \"node\": {"
    "    \"createdIndex\": 1,"
    "    \"dir\": true,"
    "    \"key\": \"/some\","
    "    \"modifiedIndex\": 2,"
    "    \"nodes\": ["
    "      {"
    "        \"createdIndex\": 6,"
    "        \"key\": \"/some/key1\","
    "        \"modifiedIndex\": 9,"
    "        \"value\": \"123\""
    "      }, {"
    "        \"createdIndex\": 7,"
    "        \"key\": \"/some/key2\","
    "        \"modifiedIndex\": 7,"
    "        \"value\": \"456\""
    "      },"
    "    ]"
    "  }"
    "}";

const char kCreateJson[] =
    "{"
    "  \"action\": \"set\","
    "  \"node\": {"
    "    \"createdIndex\": 6,"
    "    \"key\": \"/some/key\","
    "    \"modifiedIndex\": 6,"
    "    \"value\": \"123\""
    "  }"
    "}";

const char kCreateInQueueJson[] =
    "{"
    "  \"action\": \"set\","
    "  \"node\": {"
    "    \"createdIndex\": 6,"
    "    \"key\": \"/some/6\","
    "    \"modifiedIndex\": 6,"
    "    \"value\": \"123\""
    "  }"
    "}";

const char kUpdateJson[] =
    "{"
    "  \"action\": \"set\","
    "  \"node\": {"
    "    \"createdIndex\": 5,"
    "    \"key\": \"/some/key\","
    "    \"modifiedIndex\": 6,"
    "    \"value\": \"123\""
    "  },"
    "  \"prevNode\": {"
    "    \"createdIndex\": 5,"
    "    \"key\": \"/some/key\","
    "    \"modifiedIndex\": 5,"
    "    \"value\": \"old\""
    "  }"
    "}";

const char kDeleteJson[] =
    "{"
    "  \"action\": \"delete\","
    "  \"node\": {"
    "    \"createdIndex\": 5,"
    "    \"key\": \"/some/key\","
    "    \"modifiedIndex\": 6,"
    "  },"
    "  \"prevNode\": {"
    "    \"createdIndex\": 5,"
    "    \"key\": \"/some/key\","
    "    \"modifiedIndex\": 5,"
    "    \"value\": \"123\""
    "  }"
    "}";

const char kKeyNotFoundJson[] =
    "{"
    "   \"index\" : 17,"
    "   \"message\" : \"Key not found\","
    "   \"errorCode\" : 100,"
    "   \"cause\" : \"/testdir/345\""
    "}";

const char kKeyAlreadyExistsJson[] =
    "{"
    "   \"index\" : 18,"
    "   \"errorCode\" : 105,"
    "   \"message\" : \"Key already exists\","
    "   \"cause\" : \"/a\""
    "}";

const char kCompareFailedJson[] =
    "{"
    "   \"errorCode\": 101,"
    "   \"message\": \"Compare failed\","
    "   \"cause\": \"[two != one]\","
    "   \"index\": 8"
    "}";

const seconds kTimeout(1);

class MockEtcdClient : public EtcdClient {
 public:
  MockEtcdClient(const shared_ptr<libevent::Base>& base) : EtcdClient(base) {
  }

  MOCK_METHOD5(Generic,
               void(const string& key, const map<string, string>& params,
                    UrlFetcher::Verb verb, GenericResponse* resp, Task* task));
};

class MockCallbacks {
 public:
  MockCallbacks() = default;

  MOCK_METHOD2(GetAllCallback,
               void(Status status, const vector<EtcdClient::Node>& nodes));

 private:
  DISALLOW_COPY_AND_ASSIGN(MockCallbacks);
};

class EtcdTest : public ::testing::Test {
 public:
  EtcdTest()
      : base_(make_shared<libevent::Base>()), pump_(base_), client_(base_) {
  }

  shared_ptr<JsonObject> MakeJson(const string& json) {
    return make_shared<JsonObject>(json);
  }

  const shared_ptr<libevent::Base> base_;
  libevent::EventPumpThread pump_;
  StrictMock<MockCallbacks> callbacks_;
  MockEtcdClient client_;
  const map<string, string> kEmptyParams;
};

void GenericReturn(Status status, const shared_ptr<JsonObject>& json_body,
                   int64_t etcd_index, EtcdClient::GenericResponse* resp,
                   Task* task) {
  resp->etcd_index = etcd_index;
  resp->json_body = json_body;
  task->Return(status);
}

TEST_F(EtcdTest, TestGet) {
  EXPECT_CALL(client_,
              Generic(kEntryKey, kEmptyParams, UrlFetcher::Verb::GET, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kGetJson), 1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::GetResponse resp;
  client_.Get(kEntryKey, &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(9, resp.node.modified_index_);
  EXPECT_EQ("123", resp.node.value_);
}

TEST_F(EtcdTest, TestGetForInvalidKey) {
  const Status status(util::error::NOT_FOUND, "");
  EXPECT_CALL(client_,
              Generic(kEntryKey, kEmptyParams, UrlFetcher::Verb::GET, _, _))
      .WillOnce(Invoke(bind(&GenericReturn, status, MakeJson(kKeyNotFoundJson),
                            -1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::GetResponse resp;
  client_.Get(kEntryKey, &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status(status.CanonicalCode(),
                   status.error_message() + " (" + kEntryKey + ")"),
            task.status());
}

TEST_F(EtcdTest, TestGetAll) {
  Notification done;
  EXPECT_CALL(client_,
              Generic(kDirKey, kEmptyParams, UrlFetcher::Verb::GET, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kGetAllJson), 1, _4, _5)));
  EXPECT_CALL(
      callbacks_,
      GetAllCallback(
          Status::OK,
          ElementsAre(AllOf(Field(&EtcdClient::Node::modified_index_, 9),
                            Field(&EtcdClient::Node::value_, "123")),
                      AllOf(Field(&EtcdClient::Node::modified_index_, 7),
                            Field(&EtcdClient::Node::value_, "456")))))
      .WillOnce(Invoke(bind(&Notification::Notify, &done)));
  client_.GetAll(kDirKey,
                 bind(&MockCallbacks::GetAllCallback, &callbacks_, _1, _2));
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(kTimeout));
}

TEST_F(EtcdTest, TestGetAllForInvalidKey) {
  Notification done;
  const Status status(util::error::NOT_FOUND, "");
  EXPECT_CALL(client_,
              Generic(kDirKey, kEmptyParams, UrlFetcher::Verb::GET, _, _))
      .WillOnce(Invoke(bind(&GenericReturn, Status(util::error::NOT_FOUND, ""),
                            MakeJson(kKeyNotFoundJson), -1, _4, _5)));
  EXPECT_CALL(callbacks_, GetAllCallback(Status(status.CanonicalCode(),
                                                status.error_message() + " (" +
                                                    kDirKey + ")"),
                                         _))
      .WillOnce(Invoke(bind(&Notification::Notify, &done)));
  client_.GetAll(kDirKey,
                 bind(&MockCallbacks::GetAllCallback, &callbacks_, _1, _2));
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(kTimeout));
}

TEST_F(EtcdTest, TestCreate) {
  EXPECT_CALL(client_, Generic(kEntryKey,
                               AllOf(Contains(Pair(kValueParam, "123")),
                                     Contains(Pair(kPrevExistParam, kFalse))),
                               UrlFetcher::Verb::PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kCreateJson), 1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.Create(kEntryKey, "123", &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, TestCreateFails) {
  const Status status(util::error::FAILED_PRECONDITION, "");
  EXPECT_CALL(client_, Generic(kEntryKey,
                               AllOf(Contains(Pair(kValueParam, "123")),
                                     Contains(Pair(kPrevExistParam, kFalse))),
                               UrlFetcher::Verb::PUT, _, _))
      .WillOnce(Invoke(bind(&GenericReturn,
                            Status(util::error::FAILED_PRECONDITION, ""),
                            MakeJson(kKeyAlreadyExistsJson), -1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.Create(kEntryKey, "123", &resp, task.task());
  task.Wait();
  EXPECT_EQ(status, task.status());
}

TEST_F(EtcdTest, TestCreateWithTTL) {
  EXPECT_CALL(client_,
              Generic(kEntryKey, AllOf(Contains(Pair(kValueParam, "123")),
                                       Contains(Pair(kPrevExistParam, kFalse)),
                                       Contains(Pair(kTtlParam, "100"))),
                      UrlFetcher::Verb::PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kCreateJson), 1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.CreateWithTTL(kEntryKey, "123", std::chrono::duration<int>(100),
                        &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, TestCreateWithTTLFails) {
  const Status status(util::error::FAILED_PRECONDITION, "");
  EXPECT_CALL(client_,
              Generic(kEntryKey, AllOf(Contains(Pair(kValueParam, "123")),
                                       Contains(Pair(kPrevExistParam, kFalse)),
                                       Contains(Pair(kTtlParam, "100"))),
                      UrlFetcher::Verb::PUT, _, _))
      .WillOnce(Invoke(bind(&GenericReturn,
                            Status(util::error::FAILED_PRECONDITION, ""),
                            MakeJson(kKeyAlreadyExistsJson), 1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.CreateWithTTL(kEntryKey, "123", std::chrono::duration<int>(100),
                        &resp, task.task());
  task.Wait();
  EXPECT_EQ(status, task.status());
}

TEST_F(EtcdTest, TestCreateInQueue) {
  EXPECT_CALL(client_,
              Generic(kDirKey, AllOf(Contains(Pair(kValueParam, "123")),
                                     Contains(Pair(kPrevExistParam, kFalse))),
                      UrlFetcher::Verb::POST, _, _))
      .WillOnce(Invoke(bind(&GenericReturn, Status::OK,
                            MakeJson(kCreateInQueueJson), 1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::CreateInQueueResponse resp;
  client_.CreateInQueue(kDirKey, "123", &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
  EXPECT_EQ("/some/6", resp.key);
}

TEST_F(EtcdTest, TestCreateInQueueFails) {
  const Status status(util::error::FAILED_PRECONDITION, "");
  EXPECT_CALL(client_,
              Generic(kDirKey, AllOf(Contains(Pair(kValueParam, "123")),
                                     Contains(Pair(kPrevExistParam, kFalse))),
                      UrlFetcher::Verb::POST, _, _))
      .WillOnce(Invoke(bind(&GenericReturn, status,
                            MakeJson(kKeyAlreadyExistsJson), -1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::CreateInQueueResponse resp;
  client_.CreateInQueue(kDirKey, "123", &resp, task.task());
  task.Wait();
  EXPECT_EQ(status, task.status());
}

TEST_F(EtcdTest, TestUpdate) {
  EXPECT_CALL(client_, Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                               UrlFetcher::Verb::PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kUpdateJson), 1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.Update(kEntryKey, "123", 5, &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, TestUpdateFails) {
  const Status status(util::error::FAILED_PRECONDITION, "");
  EXPECT_CALL(client_, Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                               UrlFetcher::Verb::PUT, _, _))
      .WillOnce(Invoke(bind(&GenericReturn, status,
                            MakeJson(kCompareFailedJson), -1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.Update(kEntryKey, "123", 5, &resp, task.task());
  task.Wait();
  EXPECT_EQ(status, task.status());
}

TEST_F(EtcdTest, TestUpdateWithTTL) {
  EXPECT_CALL(client_,
              Generic(kEntryKey, AllOf(Contains(Pair(kPrevIndexParam, "5")),
                                       Contains(Pair(kTtlParam, "100"))),
                      UrlFetcher::Verb::PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kUpdateJson), 1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.UpdateWithTTL(kEntryKey, "123", std::chrono::duration<int>(100), 5,
                        &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, TestUpdateWithTTLFails) {
  const Status status(util::error::FAILED_PRECONDITION, "");
  EXPECT_CALL(client_,
              Generic(kEntryKey, AllOf(Contains(Pair(kPrevIndexParam, "5")),
                                       Contains(Pair(kTtlParam, "100"))),
                      UrlFetcher::Verb::PUT, _, _))
      .WillOnce(Invoke(bind(&GenericReturn, status,
                            MakeJson(kCompareFailedJson), -1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.UpdateWithTTL(kEntryKey, "123", std::chrono::duration<int>(100), 5,
                        &resp, task.task());
  task.Wait();
  EXPECT_EQ(status, task.status());
}

TEST_F(EtcdTest, TestForceSetForPreexistingKey) {
  EXPECT_CALL(client_, Generic(kEntryKey, _, UrlFetcher::Verb::PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kUpdateJson), 1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.ForceSet(kEntryKey, "123", &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, TestForceSetForNewKey) {
  EXPECT_CALL(client_, Generic(kEntryKey, _, UrlFetcher::Verb::PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kCreateJson), 1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.ForceSet(kEntryKey, "123", &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, TestForceSetWithTTLForPreexistingKey) {
  EXPECT_CALL(client_, Generic(kEntryKey, Contains(Pair(kTtlParam, "100")),
                               UrlFetcher::Verb::PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kUpdateJson), 1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.ForceSetWithTTL(kEntryKey, "123", std::chrono::duration<int>(100),
                          &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, TestForceSetWithTTLForNewKey) {
  EXPECT_CALL(client_, Generic(kEntryKey, Contains(Pair(kTtlParam, "100")),
                               UrlFetcher::Verb::PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kCreateJson), 1, _4, _5)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.ForceSetWithTTL(kEntryKey, "123", std::chrono::duration<int>(100),
                          &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, TestDelete) {
  EXPECT_CALL(client_, Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                               UrlFetcher::Verb::DELETE, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kDeleteJson), 1, _4, _5)));
  SyncTask task(base_.get());
  client_.Delete(kEntryKey, 5, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
}

TEST_F(EtcdTest, TestDeleteFails) {
  const Status status(util::error::FAILED_PRECONDITION, "");
  EXPECT_CALL(client_, Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                               UrlFetcher::Verb::DELETE, _, _))
      .WillOnce(Invoke(bind(&GenericReturn, status,
                            MakeJson(kCompareFailedJson), -1, _4, _5)));
  SyncTask task(base_.get());
  client_.Delete(kEntryKey, 5, task.task());
  task.Wait();
  EXPECT_EQ(status, task.status());
}

}  // namespace
}  // namespace cert_trans

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
