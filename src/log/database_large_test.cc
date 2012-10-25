/* -*- indent-tabs-mode: nil -*- */

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <set>
#include <stdlib.h>
#include <string>
#include <sys/resource.h>

#include "database.h"
#include "file_db.h"
#include "file_storage.h"
#include "sqlite_db.h"
#include "test_db.h"
#include "test_signer.h"
#include "testing.h"
#include "util.h"

DEFINE_int32(database_size, 0, "Number of entries to put in the test database. "
             "Be careful choosing this, as the database will fill up your disk "
             "(entries are a few kB each). Maximum is limited to 1 000 000. "
             "Also note that SQLite may be very slow with small batch sizes.");
DEFINE_int32(batch_size, 1, "Number of writes to batch together "
             "in one transaction (no effect for FileDB).");

namespace {

using ct::LoggedCertificate;
using std::string;

template <class T> class LargeDBTest : public ::testing::Test {
 protected:
  LargeDBTest() :
      test_db_(),
      test_signer_() { }

  ~LargeDBTest() {}

  void FillDatabase(int entries) {
    LoggedCertificate logged_cert;
    for (int i = 0; i < entries; ++i) {
      test_signer_.CreateUniqueFakeSignature(&logged_cert);
      EXPECT_EQ(Database::OK,
                db()->CreatePendingCertificateEntry(logged_cert));
    }
  }

  int ReadAllPendingEntries() {
    std::set<string> pending_hashes = db()->PendingHashes();
    std::set<string>::const_iterator it;
    LoggedCertificate lookup_cert;
    for (it = pending_hashes.begin(); it != pending_hashes.end(); ++it) {
      EXPECT_EQ(Database::LOOKUP_OK,
                this->db()->LookupCertificateByHash(*it, &lookup_cert));
    }
    return pending_hashes.size();
  }

  T *db() const { return test_db_.db(); }

  TestDB<T> test_db_;
  TestSigner test_signer_;
};

typedef testing::Types<FileDB, SQLiteDB> Databases;

TYPED_TEST_CASE(LargeDBTest, Databases);

TYPED_TEST(LargeDBTest, Benchmark) {
  int entries = FLAGS_database_size;
  CHECK_GE(entries, 0);
  int batch_size = FLAGS_batch_size;
  int original_log_level = FLAGS_minloglevel;

  struct rusage ru_before, ru_after;
  getrusage(RUSAGE_SELF, &ru_before);
  uint64_t realtime_before, realtime_after;
  realtime_before = util::TimeInMilliseconds();
  if (batch_size == 1 || !this->db()->Transactional()) {
    this->FillDatabase(entries);
  } else {
    CHECK_GT(batch_size, 1);
    while (entries >= batch_size) {
      this->db()->BeginTransaction();
      this->FillDatabase(batch_size);
      this->db()->EndTransaction();
      entries -= batch_size;
    }
    if (entries > 0) {
      this->db()->BeginTransaction();
      this->FillDatabase(entries);
      this->db()->EndTransaction();
    }
  }
  realtime_after = util::TimeInMilliseconds();
  getrusage(RUSAGE_SELF, &ru_after);

  FLAGS_minloglevel = 0;
  LOG(INFO) << "Real time spent creating " << FLAGS_database_size
            << " entries: " << realtime_after - realtime_before << " ms";
  LOG(INFO) << "Peak RSS delta (as reported by getrusage()) was "
            << ru_after.ru_maxrss - ru_before.ru_maxrss << " kB";
  FLAGS_minloglevel = original_log_level;

  getrusage(RUSAGE_SELF, &ru_before);
  realtime_before = util::TimeInMilliseconds();
  CHECK_EQ(FLAGS_database_size, this->ReadAllPendingEntries());
  realtime_after = util::TimeInMilliseconds();
  getrusage(RUSAGE_SELF, &ru_after);

  FLAGS_minloglevel = 0;
  LOG(INFO) << "Real time spent reading " << FLAGS_database_size
            << " entries, sorted by key: "
            << realtime_after - realtime_before << " ms";
  LOG(INFO) << "Peak RSS delta (as reported by getrusage()) was "
            << ru_after.ru_maxrss - ru_before.ru_maxrss << " kB";
  FLAGS_minloglevel = original_log_level;
}

}  // namespace

int main(int argc, char **argv) {
  ct::test::InitTesting(argv[0], &argc, &argv, true);
  CHECK_GT(FLAGS_database_size, 0) << "Please specify the test database size";
  CHECK_LE(FLAGS_database_size, 1000000)
      << "Database size exceeds allowed maximum";
  return RUN_ALL_TESTS();
}
