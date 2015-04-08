#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include "util/etcd_delete.h"
#include "util/mock_etcd.h"
#include "util/status_test_util.h"
#include "util/sync_task.h"
#include "util/testing.h"
#include "util/thread_pool.h"

using std::bind;
using std::chrono::seconds;
using std::make_pair;
using std::move;
using std::pair;
using std::string;
using std::vector;
using testing::DoAll;
using testing::Exactly;
using testing::Expectation;
using testing::InvokeWithoutArgs;
using testing::Mock;
using testing::MockFunction;
using testing::SaveArg;
using testing::StrictMock;
using testing::_;
using util::Status;
using util::SyncTask;
using util::Task;
using util::testing::StatusIs;

DECLARE_int32(etcd_delete_concurrency);

namespace cert_trans {
namespace {


class EtcdDeleteTest : public ::testing::Test {
 protected:
  EtcdDeleteTest() : pool_(1) {
    FLAGS_etcd_delete_concurrency = 2;
  }

  ThreadPool pool_;
  StrictMock<MockEtcdClient> client_;
};


typedef EtcdDeleteTest EtcdDeleteDeathTest;


TEST_F(EtcdDeleteDeathTest, ConcurrencyTooLow) {
  FLAGS_etcd_delete_concurrency = 0;
  SyncTask sync(&pool_);

  EXPECT_DEATH(EtcdDeleteKeys(&client_, {}, sync.task()),
               "FLAGS_etcd_delete_concurrency > 0");

  sync.task()->Return();
  sync.Wait();
}


TEST_F(EtcdDeleteDeathTest, NoClient) {
  SyncTask sync(&pool_);

  EXPECT_DEATH(EtcdDeleteKeys(nullptr, {}, sync.task()),
               "'client' Must be non NULL");

  sync.task()->Return();
  sync.Wait();
}


TEST_F(EtcdDeleteDeathTest, NoTask) {
  EXPECT_DEATH(EtcdDeleteKeys(&client_, {}, nullptr),
               "'task' Must be non NULL");
}


TEST_F(EtcdDeleteTest, NothingToDo) {
  SyncTask sync(&pool_);
  EtcdDeleteKeys(&client_, {}, sync.task());
  sync.Wait();
  EXPECT_OK(sync.status());
}


TEST_F(EtcdDeleteTest, AlreadyCancelled) {
  SyncTask sync(&pool_);
  sync.Cancel();
  EtcdDeleteKeys(&client_, {make_pair("/foo", 42)}, sync.task());
  sync.Wait();
  EXPECT_THAT(sync.status(), StatusIs(util::error::CANCELLED));
}


TEST_F(EtcdDeleteTest, CancelDuring) {
  vector<pair<string, int64_t> > keys{make_pair("/one", 1),
                                      make_pair("/two", 2),
                                      make_pair("/three", 3)};
  ASSERT_LT(FLAGS_etcd_delete_concurrency, keys.size());
  SyncTask sync(&pool_);

  Task* first_task(nullptr);
  Notification first;
  Task* second_task(nullptr);
  Notification second;
  EXPECT_CALL(client_, Delete("/one", 1, _))
      .WillOnce(DoAll(SaveArg<2>(&first_task),
                      InvokeWithoutArgs(&first, &Notification::Notify)));
  EXPECT_CALL(client_, Delete("/two", 2, _))
      .WillOnce(DoAll(SaveArg<2>(&second_task),
                      InvokeWithoutArgs(&second, &Notification::Notify)));
  EtcdDeleteKeys(&client_, move(keys), sync.task());

  ASSERT_TRUE(first.WaitForNotificationWithTimeout(seconds(1)));
  ASSERT_TRUE(first_task);
  ASSERT_TRUE(second.WaitForNotificationWithTimeout(seconds(1)));
  ASSERT_TRUE(second_task);

  sync.Cancel();
  first_task->Return();
  second_task->Return();

  sync.Wait();
  EXPECT_THAT(sync.status(), StatusIs(util::error::CANCELLED));
}


TEST_F(EtcdDeleteTest, WithinConcurrency) {
  vector<pair<string, int64_t> > keys{make_pair("/one", 1),
                                      make_pair("/two", 2),
                                      make_pair("/three", 3)};
  ASSERT_LT(FLAGS_etcd_delete_concurrency, keys.size());
  SyncTask sync(&pool_);

  Task* first_task(nullptr);
  Notification first;
  Task* second_task(nullptr);
  Notification second;
  EXPECT_CALL(client_, Delete("/one", 1, _))
      .WillOnce(DoAll(SaveArg<2>(&first_task),
                      InvokeWithoutArgs(&first, &Notification::Notify)));
  EXPECT_CALL(client_, Delete("/two", 2, _))
      .WillOnce(DoAll(SaveArg<2>(&second_task),
                      InvokeWithoutArgs(&second, &Notification::Notify)));
  EtcdDeleteKeys(&client_, move(keys), sync.task());

  ASSERT_TRUE(first.WaitForNotificationWithTimeout(seconds(1)));
  ASSERT_TRUE(first_task);
  ASSERT_TRUE(second.WaitForNotificationWithTimeout(seconds(1)));
  ASSERT_TRUE(second_task);

  // Make sure all the expected calls were called.
  Mock::VerifyAndClearExpectations(&client_);

  MockFunction<void()> cleanup;
  second_task->CleanupWhenDone(bind(&MockFunction<void()>::Call, &cleanup));
  Expectation first_done(EXPECT_CALL(cleanup, Call()).Times(Exactly(1)));

  // Set up the expectation for the third call, but only once one of
  // the first requests "completes".
  Task* third_task(nullptr);
  Notification third;
  EXPECT_CALL(client_, Delete("/three", 3, _))
      .After(first_done)
      .WillOnce(DoAll(SaveArg<2>(&third_task),
                      InvokeWithoutArgs(&third, &Notification::Notify)));

  second_task->Return();

  ASSERT_TRUE(third.WaitForNotificationWithTimeout(seconds(1)));
  ASSERT_TRUE(third_task);

  first_task->Return();
  third_task->Return();

  sync.Wait();
  EXPECT_OK(sync.status());
}


TEST_F(EtcdDeleteTest, ErrorHandling) {
  vector<pair<string, int64_t> > keys{make_pair("/one", 1),
                                      make_pair("/two", 2),
                                      make_pair("/three", 3)};
  ASSERT_LT(FLAGS_etcd_delete_concurrency, keys.size());
  SyncTask sync(&pool_);

  Task* first_task(nullptr);
  Notification first;
  Task* second_task(nullptr);
  Notification second;
  EXPECT_CALL(client_, Delete("/one", 1, _))
      .WillOnce(DoAll(SaveArg<2>(&first_task),
                      InvokeWithoutArgs(&first, &Notification::Notify)));
  EXPECT_CALL(client_, Delete("/two", 2, _))
      .WillOnce(DoAll(SaveArg<2>(&second_task),
                      InvokeWithoutArgs(&second, &Notification::Notify)));
  EtcdDeleteKeys(&client_, move(keys), sync.task());

  ASSERT_TRUE(first.WaitForNotificationWithTimeout(seconds(1)));
  ASSERT_TRUE(first_task);
  ASSERT_TRUE(second.WaitForNotificationWithTimeout(seconds(1)));
  ASSERT_TRUE(second_task);

  // Make sure all the expected calls were called.
  Mock::VerifyAndClearExpectations(&client_);

  second_task->Return(Status(util::error::DATA_LOSS, "things are bad"));

  // Make sure the error propagates...
  Notification first_cancelled;
  first_task->WhenCancelled(bind(&Notification::Notify, &first_cancelled));
  ASSERT_TRUE(first_cancelled.WaitForNotificationWithTimeout(seconds(1)));
  first_task->Return();

  sync.Wait();
  EXPECT_THAT(sync.status(), StatusIs(util::error::DATA_LOSS));
}


}  // namespace
}  // namespace cert_trans


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
