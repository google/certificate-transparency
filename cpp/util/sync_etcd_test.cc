#include "util/sync_etcd.h"

#include <boost/make_shared.hpp>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <map>
#include <string>

#include "util/json_wrapper.h"
#include "util/testing.h"

namespace cert_trans {


using std::list;
using std::make_pair;
using std::map;
using std::pair;
using std::string;
using testing::_;
using testing::AllOf;
using testing::Contains;
using testing::InvokeArgument;
using testing::Pair;
using util::Status;

const char kEntryKey[] = "/some/key";
const char kDirKey[] = "/some";
const char kValueParam[] = "value";
const char kPrevExistParam[] = "prevExist";
const char kPrevIndexParam[] = "prevIndex";
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
  MOCK_METHOD4(Generic,
               void(const string& key, const map<string, string>& params,
                    evhttp_cmd_type verb, const GenericCallback& cb));
};


class SyncEtcdTest : public ::testing::Test {
 public:
  boost::shared_ptr<JsonObject> MakeJson(const string& json) {
    return boost::make_shared<JsonObject>(json);
  }

  void SetUp() {
    mock_client_ = new MockEtcdClient;
    sync_client_.reset(new SyncEtcdClient(mock_client_));
  }

  MockEtcdClient* mock_client_;
  boost::scoped_ptr<SyncEtcdClient> sync_client_;
  const map<string, string> kEmptyParams;
};


TEST_F(SyncEtcdTest, TestGet) {
  EXPECT_CALL(*mock_client_,
              Generic(kEntryKey, kEmptyParams, EVHTTP_REQ_GET, _))
      .WillOnce(InvokeArgument<3>(Status(), MakeJson(kGetJson)));
  int index;
  string value;
  Status status(sync_client_->Get(kEntryKey, &index, &value));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(9, index);
  EXPECT_EQ("123", value);
}


TEST_F(SyncEtcdTest, TestGetForInvalidKey) {
  EXPECT_CALL(*mock_client_,
              Generic(kEntryKey, kEmptyParams, EVHTTP_REQ_GET, _))
      .WillOnce(InvokeArgument<3>(Status(util::error::NOT_FOUND, ""),
                                  MakeJson(kKeyNotFoundJson)));
  int index;
  string value;
  Status status(sync_client_->Get(kEntryKey, &index, &value));
  EXPECT_FALSE(status.ok());
}


TEST_F(SyncEtcdTest, TestGetAll) {
  EXPECT_CALL(*mock_client_, Generic(kDirKey, kEmptyParams, EVHTTP_REQ_GET, _))
      .WillOnce(InvokeArgument<3>(Status(), MakeJson(kGetAllJson)));
  list<pair<string, int> > expected_values;
  expected_values.push_back(make_pair("123", 9));
  expected_values.push_back(make_pair("456", 7));

  list<pair<string, int> > values;
  Status status(sync_client_->GetAll(kDirKey, &values));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(expected_values, values);
}


TEST_F(SyncEtcdTest, TestGetAllForInvalidKey) {
  EXPECT_CALL(*mock_client_, Generic(kDirKey, kEmptyParams, EVHTTP_REQ_GET, _))
      .WillOnce(InvokeArgument<3>(Status(util::error::NOT_FOUND, ""),
                                  MakeJson(kKeyNotFoundJson)));
  list<pair<string, int> > values;
  Status status(sync_client_->GetAll(kDirKey, &values));
  EXPECT_FALSE(status.ok()) << status;
}


TEST_F(SyncEtcdTest, TestCreate) {
  EXPECT_CALL(*mock_client_,
              Generic(kEntryKey,
                      AllOf(Contains(Pair(kValueParam, "123")),
                            Contains(Pair(kPrevExistParam, kFalse))),
                      EVHTTP_REQ_PUT, _))
      .WillOnce(InvokeArgument<3>(Status(), MakeJson(kCreateJson)));
  int index;
  Status status(sync_client_->Create(kEntryKey, "123", &index));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(6, index);
}


TEST_F(SyncEtcdTest, TestCreateFails) {
  EXPECT_CALL(*mock_client_,
              Generic(kEntryKey,
                      AllOf(Contains(Pair(kValueParam, "123")),
                            Contains(Pair(kPrevExistParam, kFalse))),
                      EVHTTP_REQ_PUT, _))
      .WillOnce(InvokeArgument<3>(Status(util::error::FAILED_PRECONDITION, ""),
                                  MakeJson(kKeyAlreadyExistsJson)));
  int index;
  Status status(sync_client_->Create(kEntryKey, "123", &index));
  EXPECT_FALSE(status.ok());
}


TEST_F(SyncEtcdTest, TestCreateInQueue) {
  EXPECT_CALL(*mock_client_,
              Generic(kDirKey, AllOf(Contains(Pair(kValueParam, "123")),
                                     Contains(Pair(kPrevExistParam, kFalse))),
                      EVHTTP_REQ_POST, _))
      .WillOnce(InvokeArgument<3>(Status(), MakeJson(kCreateInQueueJson)));
  int index;
  string key;
  Status status(sync_client_->CreateInQueue(kDirKey, "123", &key, &index));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(6, index);
  EXPECT_EQ("/some/6", key);
}


TEST_F(SyncEtcdTest, TestCreateInQueueFails) {
  EXPECT_CALL(*mock_client_,
              Generic(kDirKey, AllOf(Contains(Pair(kValueParam, "123")),
                                     Contains(Pair(kPrevExistParam, kFalse))),
                      EVHTTP_REQ_POST, _))
      .WillOnce(InvokeArgument<3>(Status(util::error::FAILED_PRECONDITION, ""),
                                  MakeJson(kKeyAlreadyExistsJson)));
  int index;
  string key;
  Status status(sync_client_->CreateInQueue(kDirKey, "123", &key, &index));
  EXPECT_FALSE(status.ok());
}


TEST_F(SyncEtcdTest, TestUpdate) {
  EXPECT_CALL(*mock_client_,
              Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                      EVHTTP_REQ_PUT, _))
      .WillOnce(InvokeArgument<3>(Status(), MakeJson(kUpdateJson)));
  int index;
  Status status(sync_client_->Update(kEntryKey, "123", 5, &index));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(6, index);
}


TEST_F(SyncEtcdTest, TestUpdateFails) {
  EXPECT_CALL(*mock_client_,
              Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                      EVHTTP_REQ_PUT, _))
      .WillOnce(InvokeArgument<3>(Status(util::error::FAILED_PRECONDITION, ""),
                                  MakeJson(kCompareFailedJson)));
  int index;
  Status status(sync_client_->Update(kEntryKey, "123", 5, &index));
  EXPECT_FALSE(status.ok());
}


TEST_F(SyncEtcdTest, TestDelete) {
  EXPECT_CALL(*mock_client_,
              Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                      EVHTTP_REQ_DELETE, _))
      .WillOnce(InvokeArgument<3>(Status(), MakeJson(kDeleteJson)));
  Status status(sync_client_->Delete(kEntryKey, 5));
  EXPECT_TRUE(status.ok()) << status;
}


TEST_F(SyncEtcdTest, TestDeleteFails) {
  EXPECT_CALL(*mock_client_,
              Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                      EVHTTP_REQ_DELETE, _))
      .WillOnce(InvokeArgument<3>(Status(util::error::FAILED_PRECONDITION, ""),
                                  MakeJson(kCompareFailedJson)));
  Status status(sync_client_->Delete(kEntryKey, 5));
  EXPECT_FALSE(status.ok());
}


}  // namespace cert_trans


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
