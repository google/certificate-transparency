#include "util/testing.h"

#include <event2/thread.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>

namespace cert_trans {
namespace test {

void InitTesting(const char* name, int* argc, char*** argv,
                 bool remove_flags) {
  // Change the defaults. Can be overridden on command line.
  // Log to stderr instead of log files.
  FLAGS_logtostderr = true;
  // Only log fatal messages by default.
  FLAGS_minloglevel = 3;
  ::testing::InitGoogleTest(argc, *argv);
  google::ParseCommandLineFlags(argc, argv, remove_flags);
  google::InitGoogleLogging(name);
  evthread_use_pthreads();
}

}  // namespace test
}  // namespace cert_trans
