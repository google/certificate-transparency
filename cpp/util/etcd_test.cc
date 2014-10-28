#include "util/etcd.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>

#include "util/json_wrapper.h"
#include "util/testing.h"

namespace cert_trans {

using std::list;
using std::make_pair;
using std::make_shared;
using std::map;
using std::pair;
using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;
using std::shared_ptr;
using std::string;
using testing::AllOf;
using testing::Contains;
using testing::InvokeArgument;
using testing::Pair;
using testing::_;
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

class TestableEtcdClient : public EtcdClient {
 public:
  MOCK_METHOD4(Generic,
               void(const string& key, const map<string, string>& params,
                    evhttp_cmd_type verb, const GenericCallback& cb));
};

class EtcdTest : public ::testing::Test {
 public:
  shared_ptr<JsonObject> MakeJson(const string& json) {
    return make_shared<JsonObject>(json);
  }

  void GetCallback(bool expect_success, int expect_index,
                   const string& expect_value, Status status, int index,
                   const string& value) {
    EXPECT_EQ(expect_success, status.ok());
    if (expect_success) {
      EXPECT_EQ(expect_index, index);
      EXPECT_EQ(expect_value, value);
    }
  }

  void GetAllCallback(bool expect_success,
                      const list<pair<string, int> >& expect_values,
                      Status status, const list<pair<string, int> >& values) {
    EXPECT_EQ(expect_success, status.ok());
    if (expect_success) {
      EXPECT_EQ(expect_values, values);
    }
  }

  void CreateCallback(bool expect_success, int expect_index, Status status,
                      int created_index) {
    EXPECT_EQ(expect_success, status.ok());
    if (expect_success) {
      EXPECT_EQ(expect_index, created_index);
    }
  }

  void CreateInQueueCallback(bool expect_success, const string& expect_key,
                             int expect_index, Status status,
                             const string& key, int created_index) {
    EXPECT_EQ(expect_success, status.ok());
    if (expect_success) {
      EXPECT_EQ(expect_index, created_index);
      EXPECT_EQ(expect_key, key);
    }
  }

  void UpdateCallback(bool expect_success, int expect_index, Status status,
                      int new_index) {
    EXPECT_EQ(expect_success, status.ok());
    if (expect_success) {
      EXPECT_EQ(expect_index, new_index);
    }
  }

  void DeleteCallback(bool expect_success, Status status) {
    EXPECT_EQ(expect_success, status.ok());
  }

  TestableEtcdClient client_;
  const map<string, string> kEmptyParams;
};

TEST_F(EtcdTest, TestGet) {
  EXPECT_CALL(client_, Generic(kEntryKey, kEmptyParams, EVHTTP_REQ_GET, _))
      .WillOnce(InvokeArgument<3>(Status(), MakeJson(kGetJson)));
  client_.Get(kEntryKey,
              bind(&EtcdTest::GetCallback, this, true, 9, "123", _1, _2, _3));
}

TEST_F(EtcdTest, TestGetForInvalidKey) {
  EXPECT_CALL(client_, Generic(kEntryKey, kEmptyParams, EVHTTP_REQ_GET, _))
      .WillOnce(InvokeArgument<3>(Status(util::error::NOT_FOUND, ""),
                                  MakeJson(kKeyNotFoundJson)));
  client_.Get(kEntryKey,
              bind(&EtcdTest::GetCallback, this, false, 0, "", _1, _2, _3));
}

TEST_F(EtcdTest, TestGetAll) {
  EXPECT_CALL(client_, Generic(kDirKey, kEmptyParams, EVHTTP_REQ_GET, _))
      .WillOnce(InvokeArgument<3>(Status(), MakeJson(kGetAllJson)));
  list<pair<string, int> > expected_values;
  expected_values.push_back(make_pair("123", 9));
  expected_values.push_back(make_pair("456", 7));
  client_.GetAll(kDirKey, bind(&EtcdTest::GetAllCallback, this, true,
                               expected_values, _1, _2));
}

TEST_F(EtcdTest, TestGetAllForInvalidKey) {
  EXPECT_CALL(client_, Generic(kDirKey, kEmptyParams, EVHTTP_REQ_GET, _))
      .WillOnce(InvokeArgument<3>(Status(util::error::NOT_FOUND, ""),
                                  MakeJson(kKeyNotFoundJson)));
  list<pair<string, int> > expected_values;
  client_.GetAll(kDirKey, bind(&EtcdTest::GetAllCallback, this, false,
                               expected_values, _1, _2));
}

TEST_F(EtcdTest, TestCreate) {
  EXPECT_CALL(client_, Generic(kEntryKey,
                               AllOf(Contains(Pair(kValueParam, "123")),
                                     Contains(Pair(kPrevExistParam, kFalse))),
                               EVHTTP_REQ_PUT, _))
      .WillOnce(InvokeArgument<3>(Status(), MakeJson(kCreateJson)));
  client_.Create(kEntryKey, "123",
                 bind(&EtcdTest::CreateCallback, this, true, 6, _1, _2));
}

TEST_F(EtcdTest, TestCreateFails) {
  EXPECT_CALL(client_, Generic(kEntryKey,
                               AllOf(Contains(Pair(kValueParam, "123")),
                                     Contains(Pair(kPrevExistParam, kFalse))),
                               EVHTTP_REQ_PUT, _))
      .WillOnce(InvokeArgument<3>(Status(util::error::FAILED_PRECONDITION, ""),
                                  MakeJson(kKeyAlreadyExistsJson)));
  client_.Create(kEntryKey, "123",
                 bind(&EtcdTest::CreateCallback, this, false, 0, _1, _2));
}

TEST_F(EtcdTest, TestCreateInQueue) {
  EXPECT_CALL(client_,
              Generic(kDirKey, AllOf(Contains(Pair(kValueParam, "123")),
                                     Contains(Pair(kPrevExistParam, kFalse))),
                      EVHTTP_REQ_POST, _))
      .WillOnce(InvokeArgument<3>(Status(), MakeJson(kCreateInQueueJson)));
  client_.CreateInQueue(kDirKey, "123",
                        bind(&EtcdTest::CreateInQueueCallback, this, true,
                             "/some/6", 6, _1, _2, _3));
}

TEST_F(EtcdTest, TestCreateInQueueFails) {
  EXPECT_CALL(client_,
              Generic(kDirKey, AllOf(Contains(Pair(kValueParam, "123")),
                                     Contains(Pair(kPrevExistParam, kFalse))),
                      EVHTTP_REQ_POST, _))
      .WillOnce(InvokeArgument<3>(Status(util::error::FAILED_PRECONDITION, ""),
                                  MakeJson(kKeyAlreadyExistsJson)));
  client_.CreateInQueue(kDirKey, "123", bind(&EtcdTest::CreateInQueueCallback,
                                             this, false, "", 0, _1, _2, _3));
}

TEST_F(EtcdTest, TestUpdate) {
  EXPECT_CALL(client_, Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                               EVHTTP_REQ_PUT, _))
      .WillOnce(InvokeArgument<3>(Status(), MakeJson(kUpdateJson)));
  client_.Update(kEntryKey, "123", 5,
                 bind(&EtcdTest::UpdateCallback, this, true, 6, _1, _2));
}

TEST_F(EtcdTest, TestUpdateFails) {
  EXPECT_CALL(client_, Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                               EVHTTP_REQ_PUT, _))
      .WillOnce(InvokeArgument<3>(Status(util::error::FAILED_PRECONDITION, ""),
                                  MakeJson(kCompareFailedJson)));
  client_.Update(kEntryKey, "123", 5,
                 bind(&EtcdTest::UpdateCallback, this, false, 0, _1, _2));
}

TEST_F(EtcdTest, TestDelete) {
  EXPECT_CALL(client_, Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                               EVHTTP_REQ_DELETE, _))
      .WillOnce(InvokeArgument<3>(Status(), MakeJson(kDeleteJson)));
  client_.Delete(kEntryKey, 5,
                 bind(&EtcdTest::DeleteCallback, this, true, _1));
}

TEST_F(EtcdTest, TestDeleteFails) {
  EXPECT_CALL(client_, Generic(kEntryKey, Contains(Pair(kPrevIndexParam, "5")),
                               EVHTTP_REQ_DELETE, _))
      .WillOnce(InvokeArgument<3>(Status(util::error::FAILED_PRECONDITION, ""),
                                  MakeJson(kCompareFailedJson)));
  client_.Delete(kEntryKey, 5,
                 bind(&EtcdTest::DeleteCallback, this, false, _1));
}

}  // namespace cert_trans

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
