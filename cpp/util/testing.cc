#include "util/testing.h"

#include <event2/thread.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>

namespace cert_trans {
namespace test {

void InitTesting(const char* name, int* argc, char*** argv,
                 bool remove_flags) {
  ::testing::InitGoogleTest(argc, *argv);
  google::ParseCommandLineFlags(argc, argv, remove_flags);
  google::InitGoogleLogging(name);
  google::InstallFailureSignalHandler();
  evthread_use_pthreads();
}

}  // namespace test
}  // namespace cert_trans
