#include <gtest/gtest.h>

#include "base/notification.h"
#include "util/testing.h"

namespace {


TEST(NotificationTest, BasicTests) {
  cert_trans::Notification notifier;

  ASSERT_FALSE(notifier.HasBeenNotified());
  notifier.Notify();
  notifier.WaitForNotification();
  ASSERT_TRUE(notifier.HasBeenNotified());
}


TEST(NotificationDeathTest, NotifyOnce) {
  cert_trans::Notification notifier;

  ASSERT_FALSE(notifier.HasBeenNotified());
  notifier.Notify();
  ASSERT_TRUE(notifier.HasBeenNotified());
  EXPECT_DEATH(notifier.Notify(), "Check failed: !notified_");
}


}  // namespace


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
