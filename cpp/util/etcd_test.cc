#include "util/etcd.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "net/mock_url_fetcher.h"
#include "util/json_wrapper.h"
#include "util/sync_task.h"
#include "util/testing.h"

namespace cert_trans {

using std::bind;
using std::chrono::seconds;
using std::make_pair;
using std::make_shared;
using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;
using std::shared_ptr;
using std::string;
using std::to_string;
using testing::ElementsAre;
using testing::Invoke;
using testing::IsEmpty;
using testing::Pair;
using testing::StrCaseEq;
using testing::StrictMock;
using testing::_;
using util::Status;
using util::SyncTask;
using util::Task;

namespace {

typedef UrlFetcher::Request FetchRequest;

const char kEntryKey[] = "/some/key";
const char kDirKey[] = "/some";
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
    "    \"createdIndex\": 7,"
    "    \"key\": \"/some/key\","
    "    \"modifiedIndex\": 7,"
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

const char kEtcdHost[] = "etcd.example.net";
const int kEtcdPort = 4242;

class EtcdTest : public ::testing::Test {
 public:
  EtcdTest()
      : base_(make_shared<libevent::Base>()),
        pump_(base_),
        client_(base_, &url_fetcher_, kEtcdHost, kEtcdPort) {
  }

  shared_ptr<JsonObject> MakeJson(const string& json) {
    return make_shared<JsonObject>(json);
  }

  const shared_ptr<libevent::Base> base_;
  StrictMock<MockUrlFetcher> url_fetcher_;
  libevent::EventPumpThread pump_;
  EtcdClient client_;
};

string GetEtcdUrl(const string& key) {
  CHECK(!key.empty() && key[0] == '/') << "key isn't slash-prefixed: " << key;
  return "http://" + string(kEtcdHost) + ":" + to_string(kEtcdPort) +
         "/v2/keys" + key;
}

void HandleFetch(Status status, int status_code,
                 const UrlFetcher::Headers& headers, const string& body,
                 const UrlFetcher::Request& req, UrlFetcher::Response* resp,
                 Task* task) {
  resp->status_code = status_code;
  resp->headers = headers;
  resp->body = body;
  task->Return(status);
}

TEST_F(EtcdTest, TestGet) {
  EXPECT_CALL(url_fetcher_,
              Fetch(IsUrlFetchRequest(UrlFetcher::Verb::GET,
                                      URL(GetEtcdUrl(kEntryKey) +
                                          "?consistent=true&quorum=true"),
                                      IsEmpty(), ""),
                    _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "11")},
                      kGetJson, _1, _2, _3)));

  SyncTask task(base_.get());
  EtcdClient::GetResponse resp;
  client_.Get(kEntryKey, &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(11, resp.etcd_index);
  EXPECT_EQ(9, resp.node.modified_index_);
  EXPECT_EQ("123", resp.node.value_);
}

TEST_F(EtcdTest, TestGetForInvalidKey) {
  EXPECT_CALL(url_fetcher_,
              Fetch(IsUrlFetchRequest(UrlFetcher::Verb::GET,
                                      URL(GetEtcdUrl(kEntryKey) +
                                          "?consistent=true&quorum=true"),
                                      IsEmpty(), ""),
                    _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 404,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "17")},
                      kKeyNotFoundJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::GetResponse resp;
  client_.Get(kEntryKey, &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status(util::error::NOT_FOUND,
                   "Key not found (" + string(kEntryKey) + ")"),
            task.status());
}

TEST_F(EtcdTest, TestGetAll) {
  EXPECT_CALL(url_fetcher_,
              Fetch(IsUrlFetchRequest(UrlFetcher::Verb::GET,
                                      URL(GetEtcdUrl(kDirKey) +
                                          "?consistent=true&quorum=true"),
                                      IsEmpty(), ""),
                    _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kGetAllJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::GetResponse resp;
  client_.Get(kDirKey, &resp, task.task());
  task.Wait();
  ASSERT_EQ(Status::OK, task.status());
  EXPECT_TRUE(resp.node.is_dir_);
  ASSERT_EQ(2, resp.node.nodes_.size());
  EXPECT_EQ(9, resp.node.nodes_[0].modified_index_);
  EXPECT_EQ("123", resp.node.nodes_[0].value_);
  EXPECT_EQ(7, resp.node.nodes_[1].modified_index_);
  EXPECT_EQ("456", resp.node.nodes_[1].value_);
}

TEST_F(EtcdTest, TestCreate) {
  EXPECT_CALL(
      url_fetcher_,
      Fetch(IsUrlFetchRequest(
                UrlFetcher::Verb::PUT, URL(GetEtcdUrl(kEntryKey)),
                ElementsAre(Pair(StrCaseEq("content-type"),
                                 "application/x-www-form-urlencoded")),
                "consistent=true&prevExist=false&quorum=true&value=123"),
            _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kCreateJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.Create(kEntryKey, "123", &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(7, resp.etcd_index);
}

TEST_F(EtcdTest, TestCreateFails) {
  EXPECT_CALL(
      url_fetcher_,
      Fetch(IsUrlFetchRequest(
                UrlFetcher::Verb::PUT, URL(GetEtcdUrl(kEntryKey)),
                ElementsAre(Pair(StrCaseEq("content-type"),
                                 "application/x-www-form-urlencoded")),
                "consistent=true&prevExist=false&quorum=true&value=123"),
            _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 412,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kKeyAlreadyExistsJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.Create(kEntryKey, "123", &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status(util::error::FAILED_PRECONDITION, "Key already exists"),
            task.status());
}

TEST_F(EtcdTest, TestCreateWithTTL) {
  EXPECT_CALL(
      url_fetcher_,
      Fetch(
          IsUrlFetchRequest(
              UrlFetcher::Verb::PUT, URL(GetEtcdUrl(kEntryKey)),
              ElementsAre(Pair(StrCaseEq("content-type"),
                               "application/x-www-form-urlencoded")),
              "consistent=true&prevExist=false&quorum=true&ttl=100&value=123"),
          _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kCreateJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.CreateWithTTL(kEntryKey, "123", std::chrono::duration<int>(100),
                        &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(7, resp.etcd_index);
}

TEST_F(EtcdTest, TestCreateWithTTLFails) {
  EXPECT_CALL(
      url_fetcher_,
      Fetch(
          IsUrlFetchRequest(
              UrlFetcher::Verb::PUT, URL(GetEtcdUrl(kEntryKey)),
              ElementsAre(Pair(StrCaseEq("content-type"),
                               "application/x-www-form-urlencoded")),
              "consistent=true&prevExist=false&quorum=true&ttl=100&value=123"),
          _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 412,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kKeyAlreadyExistsJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.CreateWithTTL(kEntryKey, "123", std::chrono::duration<int>(100),
                        &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status(util::error::FAILED_PRECONDITION, "Key already exists"),
            task.status());
}

TEST_F(EtcdTest, TestCreateInQueue) {
  EXPECT_CALL(
      url_fetcher_,
      Fetch(IsUrlFetchRequest(
                UrlFetcher::Verb::POST, URL(GetEtcdUrl(kDirKey)),
                ElementsAre(Pair(StrCaseEq("content-type"),
                                 "application/x-www-form-urlencoded")),
                "consistent=true&prevExist=false&quorum=true&value=123"),
            _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kCreateInQueueJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::CreateInQueueResponse resp;
  client_.CreateInQueue(kDirKey, "123", &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
  EXPECT_EQ("/some/6", resp.key);
}

TEST_F(EtcdTest, TestCreateInQueueFails) {
  EXPECT_CALL(
      url_fetcher_,
      Fetch(IsUrlFetchRequest(
                UrlFetcher::Verb::POST, URL(GetEtcdUrl(kDirKey)),
                ElementsAre(Pair(StrCaseEq("content-type"),
                                 "application/x-www-form-urlencoded")),
                "consistent=true&prevExist=false&quorum=true&value=123"),
            _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 412,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kKeyAlreadyExistsJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::CreateInQueueResponse resp;
  client_.CreateInQueue(kDirKey, "123", &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status(util::error::FAILED_PRECONDITION, "Key already exists"),
            task.status());
}

TEST_F(EtcdTest, TestUpdate) {
  EXPECT_CALL(url_fetcher_,
              Fetch(IsUrlFetchRequest(
                        UrlFetcher::Verb::PUT, URL(GetEtcdUrl(kEntryKey)),
                        ElementsAre(Pair(StrCaseEq("content-type"),
                                         "application/x-www-form-urlencoded")),
                        "consistent=true&prevIndex=5&quorum=true&value=123"),
                    _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kUpdateJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.Update(kEntryKey, "123", 5, &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, TestUpdateFails) {
  EXPECT_CALL(url_fetcher_,
              Fetch(IsUrlFetchRequest(
                        UrlFetcher::Verb::PUT, URL(GetEtcdUrl(kEntryKey)),
                        ElementsAre(Pair(StrCaseEq("content-type"),
                                         "application/x-www-form-urlencoded")),
                        "consistent=true&prevIndex=5&quorum=true&value=123"),
                    _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 412,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kCompareFailedJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.Update(kEntryKey, "123", 5, &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status(util::error::FAILED_PRECONDITION, "Compare failed"),
            task.status());
}

TEST_F(EtcdTest, TestUpdateWithTTL) {
  EXPECT_CALL(
      url_fetcher_,
      Fetch(IsUrlFetchRequest(
                UrlFetcher::Verb::PUT, URL(GetEtcdUrl(kEntryKey)),
                ElementsAre(Pair(StrCaseEq("content-type"),
                                 "application/x-www-form-urlencoded")),
                "consistent=true&prevIndex=5&quorum=true&ttl=100&value=123"),
            _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kUpdateJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.UpdateWithTTL(kEntryKey, "123", std::chrono::duration<int>(100), 5,
                        &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, TestUpdateWithTTLFails) {
  EXPECT_CALL(
      url_fetcher_,
      Fetch(IsUrlFetchRequest(
                UrlFetcher::Verb::PUT, URL(GetEtcdUrl(kEntryKey)),
                ElementsAre(Pair(StrCaseEq("content-type"),
                                 "application/x-www-form-urlencoded")),
                "consistent=true&prevIndex=5&quorum=true&ttl=100&value=123"),
            _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 412,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kCompareFailedJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.UpdateWithTTL(kEntryKey, "123", std::chrono::duration<int>(100), 5,
                        &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status(util::error::FAILED_PRECONDITION, "Compare failed"),
            task.status());
}

TEST_F(EtcdTest, TestForceSetForPreexistingKey) {
  EXPECT_CALL(url_fetcher_,
              Fetch(IsUrlFetchRequest(
                        UrlFetcher::Verb::PUT, URL(GetEtcdUrl(kEntryKey)),
                        ElementsAre(Pair(StrCaseEq("content-type"),
                                         "application/x-www-form-urlencoded")),
                        "consistent=true&quorum=true&value=123"),
                    _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kUpdateJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.ForceSet(kEntryKey, "123", &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, TestForceSetForNewKey) {
  EXPECT_CALL(url_fetcher_,
              Fetch(IsUrlFetchRequest(
                        UrlFetcher::Verb::PUT, URL(GetEtcdUrl(kEntryKey)),
                        ElementsAre(Pair(StrCaseEq("content-type"),
                                         "application/x-www-form-urlencoded")),
                        "consistent=true&quorum=true&value=123"),
                    _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kCreateJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.ForceSet(kEntryKey, "123", &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(7, resp.etcd_index);
}

TEST_F(EtcdTest, TestForceSetWithTTLForPreexistingKey) {
  EXPECT_CALL(url_fetcher_,
              Fetch(IsUrlFetchRequest(
                        UrlFetcher::Verb::PUT, URL(GetEtcdUrl(kEntryKey)),
                        ElementsAre(Pair(StrCaseEq("content-type"),
                                         "application/x-www-form-urlencoded")),
                        "consistent=true&quorum=true&ttl=100&value=123"),
                    _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kUpdateJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.ForceSetWithTTL(kEntryKey, "123", std::chrono::duration<int>(100),
                          &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, TestForceSetWithTTLForNewKey) {
  EXPECT_CALL(url_fetcher_,
              Fetch(IsUrlFetchRequest(
                        UrlFetcher::Verb::PUT, URL(GetEtcdUrl(kEntryKey)),
                        ElementsAre(Pair(StrCaseEq("content-type"),
                                         "application/x-www-form-urlencoded")),
                        "consistent=true&quorum=true&ttl=100&value=123"),
                    _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kCreateJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Response resp;
  client_.ForceSetWithTTL(kEntryKey, "123", std::chrono::duration<int>(100),
                          &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
  EXPECT_EQ(7, resp.etcd_index);
}

TEST_F(EtcdTest, TestDelete) {
  EXPECT_CALL(
      url_fetcher_,
      Fetch(IsUrlFetchRequest(UrlFetcher::Verb::DELETE,
                              URL(GetEtcdUrl(kEntryKey) +
                                  "?consistent=true&prevIndex=5&quorum=true"),
                              IsEmpty(), ""),
            _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kDeleteJson, _1, _2, _3)));
  SyncTask task(base_.get());
  client_.Delete(kEntryKey, 5, task.task());
  task.Wait();
  EXPECT_EQ(Status::OK, task.status());
}

TEST_F(EtcdTest, TestDeleteFails) {
  EXPECT_CALL(
      url_fetcher_,
      Fetch(IsUrlFetchRequest(UrlFetcher::Verb::DELETE,
                              URL(GetEtcdUrl(kEntryKey) +
                                  "?consistent=true&prevIndex=5&quorum=true"),
                              IsEmpty(), ""),
            _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 412,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "1")},
                      kCompareFailedJson, _1, _2, _3)));
  SyncTask task(base_.get());
  client_.Delete(kEntryKey, 5, task.task());
  task.Wait();
  EXPECT_EQ(Status(util::error::FAILED_PRECONDITION, "Compare failed"),
            task.status());
}

}  // namespace
}  // namespace cert_trans

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
