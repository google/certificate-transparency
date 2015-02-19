#include "util/sync_etcd.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>

#include "util/json_wrapper.h"
#include "util/testing.h"

namespace cert_trans {

namespace {

using std::make_pair;
using std::make_shared;
using std::map;
using std::pair;
using std::placeholders::_4;
using std::placeholders::_5;
using std::shared_ptr;
using std::string;
using std::unique_ptr;
using std::vector;
using testing::AllOf;
using testing::Contains;
using testing::Invoke;
using testing::Pair;
using testing::_;
using util::Status;
using util::Task;

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


class MockEtcdClient : public EtcdClient {
 public:
  MockEtcdClient(const shared_ptr<libevent::Base>& base) : EtcdClient(base) {
  }

  MOCK_METHOD5(Generic,
               void(const string& key, const map<string, string>& params,
                    evhttp_cmd_type verb, GenericResponse* resp, Task* task));
};


class SyncEtcdTest : public ::testing::Test {
 public:
  SyncEtcdTest()
      : base_(make_shared<libevent::Base>()),
        pump_(base_),
        mock_client_(base_) {
  }

  shared_ptr<JsonObject> MakeJson(const string& json) {
    return make_shared<JsonObject>(json);
  }

  void SetUp() {
    sync_client_.reset(new SyncEtcdClient(&mock_client_));
  }

  const shared_ptr<libevent::Base> base_;
  libevent::EventPumpThread pump_;
  MockEtcdClient mock_client_;
  unique_ptr<SyncEtcdClient> sync_client_;
  const map<string, string> kEmptyParams;
};


void GenericReturn(Status status, const shared_ptr<JsonObject>& json_body,
                   int64_t etcd_index, EtcdClient::GenericResponse* resp,
                   Task* task) {
  resp->etcd_index = etcd_index;
  resp->json_body = json_body;
  task->Return(status);
}

TEST_F(SyncEtcdTest, TestGet) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey, kEmptyParams, EVHTTP_REQ_GET, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kGetJson), 1, _4, _5)));
  EtcdClient::Node node;
  Status status(sync_client_->Get(kEntryKey, &node));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(9, node.modified_index_);
  EXPECT_EQ("123", node.value_);
}


TEST_F(SyncEtcdTest, TestGetForInvalidKey) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey, kEmptyParams, EVHTTP_REQ_GET, _, _))
      .WillOnce(Invoke(bind(&GenericReturn, Status(util::error::NOT_FOUND, ""),
                            MakeJson(kKeyNotFoundJson), 1, _4, _5)));
  EtcdClient::Node node;
  Status status(sync_client_->Get(kEntryKey, &node));
  EXPECT_FALSE(status.ok());
}


TEST_F(SyncEtcdTest, TestGetAll) {
  EXPECT_CALL(mock_client_,
              Generic(kDirKey, kEmptyParams, EVHTTP_REQ_GET, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kGetAllJson), 1, _4, _5)));
  vector<pair<string, int> > expected_values;
  expected_values.push_back(make_pair("123", 9));
  expected_values.push_back(make_pair("456", 7));

  vector<EtcdClient::Node> nodes;
  Status status(sync_client_->GetAll(kDirKey, &nodes));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(expected_values.size(), nodes.size());
  for (size_t i = 0; i < nodes.size(); ++i) {
    EXPECT_EQ(expected_values[i].first, nodes[i].value_);
    EXPECT_EQ(expected_values[i].second, nodes[i].modified_index_);
  }
}


TEST_F(SyncEtcdTest, TestGetAllForInvalidKey) {
  EXPECT_CALL(mock_client_,
              Generic(kDirKey, kEmptyParams, EVHTTP_REQ_GET, _, _))
      .WillOnce(Invoke(bind(&GenericReturn, Status(util::error::NOT_FOUND, ""),
                            MakeJson(kKeyNotFoundJson), 1, _4, _5)));
  vector<EtcdClient::Node> nodes;
  Status status(sync_client_->GetAll(kDirKey, &nodes));
  EXPECT_FALSE(status.ok()) << status;
}


TEST_F(SyncEtcdTest, TestCreate) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey,
                      AllOf(Contains(Pair(kValueParam, "123")),
                            Contains(Pair(kPrevExistParam, kFalse))),
                      EVHTTP_REQ_PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kCreateJson), 1, _4, _5)));
  int64_t index;
  Status status(sync_client_->Create(kEntryKey, "123", &index));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(6, index);
}


TEST_F(SyncEtcdTest, TestCreateFails) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey,
                      AllOf(Contains(Pair(kValueParam, "123")),
                            Contains(Pair(kPrevExistParam, kFalse))),
                      EVHTTP_REQ_PUT, _, _))
      .WillOnce(Invoke(bind(&GenericReturn,
                            Status(util::error::FAILED_PRECONDITION, ""),
                            MakeJson(kKeyAlreadyExistsJson), 1, _4, _5)));
  int64_t index;
  Status status(sync_client_->Create(kEntryKey, "123", &index));
  EXPECT_FALSE(status.ok());
}


TEST_F(SyncEtcdTest, TestCreateWithTTL) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey, AllOf(Contains(Pair(kValueParam, "123")),
                                       Contains(Pair(kPrevExistParam, kFalse)),
                                       Contains(Pair(kTtlParam, "100"))),
                      EVHTTP_REQ_PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kCreateJson), 1, _4, _5)));
  int64_t index;
  Status status(sync_client_->CreateWithTTL(kEntryKey, "123",
                                            std::chrono::duration<int>(100),
                                            &index));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(6, index);
}


TEST_F(SyncEtcdTest, TestCreateWithTTLFails) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey, AllOf(Contains(Pair(kValueParam, "123")),
                                       Contains(Pair(kPrevExistParam, kFalse)),
                                       Contains(Pair(kTtlParam, "100"))),
                      EVHTTP_REQ_PUT, _, _))
      .WillOnce(Invoke(bind(&GenericReturn,
                            Status(util::error::FAILED_PRECONDITION, ""),
                            MakeJson(kKeyAlreadyExistsJson), 1, _4, _5)));
  int64_t index;
  Status status(sync_client_->CreateWithTTL(kEntryKey, "123",
                                            std::chrono::duration<int>(100),
                                            &index));
  EXPECT_FALSE(status.ok());
}


TEST_F(SyncEtcdTest, TestCreateInQueue) {
  EXPECT_CALL(mock_client_,
              Generic(kDirKey, AllOf(Contains(Pair(kValueParam, "123")),
                                     Contains(Pair(kPrevExistParam, kFalse))),
                      EVHTTP_REQ_POST, _, _))
      .WillOnce(Invoke(bind(&GenericReturn, Status::OK,
                            MakeJson(kCreateInQueueJson), 1, _4, _5)));
  int64_t index;
  string key;
  Status status(sync_client_->CreateInQueue(kDirKey, "123", &key, &index));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(6, index);
  EXPECT_EQ("/some/6", key);
}


TEST_F(SyncEtcdTest, TestCreateInQueueFails) {
  EXPECT_CALL(mock_client_,
              Generic(kDirKey, AllOf(Contains(Pair(kValueParam, "123")),
                                     Contains(Pair(kPrevExistParam, kFalse))),
                      EVHTTP_REQ_POST, _, _))
      .WillOnce(Invoke(bind(&GenericReturn,
                            Status(util::error::FAILED_PRECONDITION, ""),
                            MakeJson(kKeyAlreadyExistsJson), 1, _4, _5)));
  int64_t index;
  string key;
  Status status(sync_client_->CreateInQueue(kDirKey, "123", &key, &index));
  EXPECT_FALSE(status.ok());
}


TEST_F(SyncEtcdTest, TestUpdate) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                      EVHTTP_REQ_PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kUpdateJson), 1, _4, _5)));
  int64_t index;
  Status status(sync_client_->Update(kEntryKey, "123", 5, &index));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(6, index);
}


TEST_F(SyncEtcdTest, TestUpdateFails) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                      EVHTTP_REQ_PUT, _, _))
      .WillOnce(Invoke(bind(&GenericReturn,
                            Status(util::error::FAILED_PRECONDITION, ""),
                            MakeJson(kCompareFailedJson), 1, _4, _5)));
  int64_t index;
  Status status(sync_client_->Update(kEntryKey, "123", 5, &index));
  EXPECT_FALSE(status.ok());
}


TEST_F(SyncEtcdTest, TestUpdateWithTTL) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey, AllOf(Contains(Pair(kPrevIndexParam, "5")),
                                       Contains(Pair(kTtlParam, "100"))),
                      EVHTTP_REQ_PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kUpdateJson), 1, _4, _5)));
  int64_t index;
  Status status(sync_client_->UpdateWithTTL(kEntryKey, "123",
                                            std::chrono::duration<int>(100), 5,
                                            &index));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(6, index);
}


TEST_F(SyncEtcdTest, TestUpdateWithTTLFails) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey, AllOf(Contains(Pair(kPrevIndexParam, "5")),
                                       Contains(Pair(kTtlParam, "100"))),
                      EVHTTP_REQ_PUT, _, _))
      .WillOnce(Invoke(bind(&GenericReturn,
                            Status(util::error::FAILED_PRECONDITION, ""),
                            MakeJson(kCompareFailedJson), 1, _4, _5)));
  int64_t index;
  Status status(sync_client_->UpdateWithTTL(kEntryKey, "123",
                                            std::chrono::duration<int>(100), 5,
                                            &index));
  EXPECT_FALSE(status.ok());
}


TEST_F(SyncEtcdTest, TestForceSetForPreexistingEntry) {
  EXPECT_CALL(mock_client_, Generic(kEntryKey, _, EVHTTP_REQ_PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kUpdateJson), 1, _4, _5)));
  int64_t index;
  Status status(sync_client_->ForceSet(kEntryKey, "123", &index));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(6, index);
}


TEST_F(SyncEtcdTest, TestForceSetForNewEntry) {
  EXPECT_CALL(mock_client_, Generic(kEntryKey, _, EVHTTP_REQ_PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kCreateJson), 1, _4, _5)));
  int64_t index;
  Status status(sync_client_->ForceSet(kEntryKey, "123", &index));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(6, index);
}


TEST_F(SyncEtcdTest, TestForceSetWithTTLForPreexistingEntry) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey, Contains(Pair(kTtlParam, "100")),
                      EVHTTP_REQ_PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kUpdateJson), 1, _4, _5)));
  int64_t index;
  Status status(sync_client_->ForceSetWithTTL(kEntryKey, "123",
                                              std::chrono::duration<int>(100),
                                              &index));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(6, index);
}


TEST_F(SyncEtcdTest, TestForceSetWithTTLForNewEntry) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey, Contains(Pair(kTtlParam, "100")),
                      EVHTTP_REQ_PUT, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kCreateJson), 1, _4, _5)));
  int64_t index;
  Status status(sync_client_->ForceSetWithTTL(kEntryKey, "123",
                                              std::chrono::duration<int>(100),
                                              &index));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(6, index);
}


TEST_F(SyncEtcdTest, TestDelete) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                      EVHTTP_REQ_DELETE, _, _))
      .WillOnce(Invoke(
          bind(&GenericReturn, Status::OK, MakeJson(kDeleteJson), 1, _4, _5)));
  Status status(sync_client_->Delete(kEntryKey, 5));
  EXPECT_TRUE(status.ok()) << status;
}


TEST_F(SyncEtcdTest, TestDeleteFails) {
  EXPECT_CALL(mock_client_,
              Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                      EVHTTP_REQ_DELETE, _, _))
      .WillOnce(Invoke(bind(&GenericReturn,
                            Status(util::error::FAILED_PRECONDITION, ""),
                            MakeJson(kCompareFailedJson), 1, _4, _5)));
  Status status(sync_client_->Delete(kEntryKey, 5));
  EXPECT_FALSE(status.ok());
}


}  // namespace
}  // namespace cert_trans


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
