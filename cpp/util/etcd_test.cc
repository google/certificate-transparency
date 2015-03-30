#include "util/etcd.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "net/mock_url_fetcher.h"
#include "util/json_wrapper.h"
#include "util/libevent_wrapper.h"
#include "util/status_test_util.h"
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
using util::testing::StatusIs;

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
        client_(&url_fetcher_, kEtcdHost, kEtcdPort) {
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

TEST_F(EtcdTest, Get) {
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
  client_.Get(string(kEntryKey), &resp, task.task());
  task.Wait();
  EXPECT_OK(task);
  EXPECT_EQ(11, resp.etcd_index);
  EXPECT_EQ(9, resp.node.modified_index_);
  EXPECT_EQ("123", resp.node.value_);
}

TEST_F(EtcdTest, GetRecursive) {
  EXPECT_CALL(url_fetcher_,
              Fetch(IsUrlFetchRequest(
                        UrlFetcher::Verb::GET,
                        URL(GetEtcdUrl(kEntryKey) +
                            "?consistent=true&quorum=true&recursive=true"),
                        IsEmpty(), ""),
                    _, _))
      .WillOnce(
          Invoke(bind(HandleFetch, Status::OK, 200,
                      UrlFetcher::Headers{make_pair("x-etcd-index", "11")},
                      kGetJson, _1, _2, _3)));

  SyncTask task(base_.get());
  EtcdClient::Request req(kEntryKey);
  req.recursive = true;
  EtcdClient::GetResponse resp;
  client_.Get(req, &resp, task.task());
  task.Wait();
  EXPECT_OK(task);
  EXPECT_EQ(11, resp.etcd_index);
  EXPECT_EQ(9, resp.node.modified_index_);
  EXPECT_EQ("123", resp.node.value_);
}

TEST_F(EtcdTest, GetForInvalidKey) {
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
  client_.Get(string(kEntryKey), &resp, task.task());
  task.Wait();
  EXPECT_THAT(task.status(),
              StatusIs(util::error::NOT_FOUND,
                       "Key not found (" + string(kEntryKey) + ")"));
}

TEST_F(EtcdTest, GetAll) {
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
  client_.Get(string(kDirKey), &resp, task.task());
  task.Wait();
  ASSERT_OK(task);
  EXPECT_TRUE(resp.node.is_dir_);
  ASSERT_EQ(2, resp.node.nodes_.size());
  EXPECT_EQ(9, resp.node.nodes_[0].modified_index_);
  EXPECT_EQ("123", resp.node.nodes_[0].value_);
  EXPECT_EQ(7, resp.node.nodes_[1].modified_index_);
  EXPECT_EQ("456", resp.node.nodes_[1].value_);
}

TEST_F(EtcdTest, GetWaitTooOld) {
  const int kOldIndex(42);
  const int kNewIndex(2015);
  EXPECT_CALL(url_fetcher_,
              Fetch(IsUrlFetchRequest(UrlFetcher::Verb::GET,
                                      URL(GetEtcdUrl(kEntryKey) +
                                          "?consistent=true&quorum=false&"
                                          "recursive=true&wait=true&"
                                          "waitIndex=" +
                                          to_string(kOldIndex)),
                                      IsEmpty(), ""),
                    _, _))
      .WillOnce(Invoke(bind(
          HandleFetch, Status::OK, 404,
          UrlFetcher::Headers{make_pair("x-etcd-index", to_string(kNewIndex))},
          kKeyNotFoundJson, _1, _2, _3)));
  SyncTask task(base_.get());
  EtcdClient::Request req(kEntryKey);
  req.recursive = true;
  req.wait_index = kOldIndex;
  EtcdClient::GetResponse resp;
  client_.Get(req, &resp, task.task());
  task.Wait();
  EXPECT_EQ(Status(util::error::NOT_FOUND,
                   "Key not found (" + string(kEntryKey) + ")"),
            task.status());
  EXPECT_EQ(kNewIndex, resp.etcd_index);
}

TEST_F(EtcdTest, Create) {
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
  EXPECT_OK(task);
  EXPECT_EQ(7, resp.etcd_index);
}

TEST_F(EtcdTest, CreateFails) {
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
  EXPECT_THAT(task.status(), StatusIs(util::error::FAILED_PRECONDITION,
                                      "Key already exists"));
}

TEST_F(EtcdTest, CreateWithTTL) {
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
  EXPECT_OK(task);
  EXPECT_EQ(7, resp.etcd_index);
}

TEST_F(EtcdTest, CreateWithTTLFails) {
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
  EXPECT_THAT(task.status(), StatusIs(util::error::FAILED_PRECONDITION,
                                      "Key already exists"));
}

TEST_F(EtcdTest, Update) {
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
  EXPECT_OK(task);
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, UpdateFails) {
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
  EXPECT_THAT(task.status(),
              StatusIs(util::error::FAILED_PRECONDITION, "Compare failed"));
}

TEST_F(EtcdTest, UpdateWithTTL) {
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
  EXPECT_OK(task);
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, UpdateWithTTLFails) {
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
  EXPECT_THAT(task.status(),
              StatusIs(util::error::FAILED_PRECONDITION, "Compare failed"));
}

TEST_F(EtcdTest, ForceSetForPreexistingKey) {
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
  EXPECT_OK(task);
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, ForceSetForNewKey) {
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
  EXPECT_OK(task);
  EXPECT_EQ(7, resp.etcd_index);
}

TEST_F(EtcdTest, ForceSetWithTTLForPreexistingKey) {
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
  EXPECT_OK(task);
  EXPECT_EQ(6, resp.etcd_index);
}

TEST_F(EtcdTest, ForceSetWithTTLForNewKey) {
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
  EXPECT_OK(task);
  EXPECT_EQ(7, resp.etcd_index);
}

TEST_F(EtcdTest, Delete) {
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
  EXPECT_OK(task);
}

TEST_F(EtcdTest, DeleteFails) {
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
  EXPECT_THAT(task.status(),
              StatusIs(util::error::FAILED_PRECONDITION, "Compare failed"));
}

}  // namespace
}  // namespace cert_trans

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
