#include <fstream>
#include <set>
#include <string>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/types.h"
#include "../proto/ct.pb.h"
#include "../util/util.h"
#include "LogDB.h"
#include "LogDBTestConstants.h"


static FailReport report;

// The main function gets as input a temporary directory, tmp_dir.
// We create the database in tmp_dir/ct; and the report in tmp_dir/report.
static const char kWorkingDir[] = "ct";
static const char kReportFile[] = "report";

static void MakeReport(const std::string &tmp_dir) {
  if (access(tmp_dir.c_str(), W_OK) < 0)
    return;
  std::string res;
  report.SerializeToString(&res);
  std::string report_loc(tmp_dir + "/" + kReportFile);
  std::ofstream report_file(report_loc.c_str(),
                            std::ios::out | std::ios::trunc | std::ios::binary);
  assert(report_file.good());
  report_file.write(res.data(), res.length());
  assert(report_file.good());
  report_file.close();
}

namespace {

// A class that behaves exactly like FileDB, except it counts file ops
// and fails at a specific point.
class FailDB : public FileDB {
 public:
  FailDB(const std::string &tmp_dir, unsigned storage_depth,
         unsigned fail_point, bool crash)
      : FileDB(tmp_dir + "/" + kWorkingDir, storage_depth),
        tmp_dir_(tmp_dir),
        op_count_(0),
        fail_point_(fail_point),
        crash_(crash),
        failed_(false) {}

 bool Failed() const { return failed_; }

 private:
  int mkdir(const char *path, mode_t mode) {
    if (fail_point_ == op_count_++) {
      failed_ = true;
      MakeReport(tmp_dir_);
      if (crash_) {
        exit(0);
      } else {
        errno = EIO;
        return -1;
      }
    }
    return ::mkdir(path, mode);
  }

  int remove(const char *path) {
    if (fail_point_ == op_count_++) {
      failed_ = true;
      MakeReport(tmp_dir_);
      if (crash_) {
        exit(0);
      } else {
        errno = EIO;
        return -1;
      }
    }
    return ::remove(path);
  }

  int rename(const char *old_name, const char *new_name) {
    if (fail_point_ == op_count_++) {
      failed_ = true;
      MakeReport(tmp_dir_);
      if (crash_) {
        exit(0);
      } else {
        errno = EIO;
        return -1;
      }
    }
    return ::rename(old_name, new_name);
  }

  std::string tmp_dir_;
  unsigned op_count_;
  unsigned fail_point_;
  bool crash_; // If true, crash on fail.
  bool failed_; // True if we have already failed.
};

}  // namespace

static FailReport ReadReport(const std::string &tmp_dir) {
  bstring result;
  bool read_success = util::ReadBinaryFile(tmp_dir + "/" + kReportFile, &result);
  assert(read_success);

  FailReport ret;
  ret.ParseFromString(result);
  return ret;
}

// Returns true if no file ops failed; false otherwise.
static void MakeLog(FailDB *db) {
  report.set_op(FailReport::INIT);
  db->Init();

  for (size_t segment = 0, offset = 0; segment < logdbtest::kNumberOfSegments;
       offset += logdbtest::kSegmentSizes[segment++]) {
    report.set_index(0);
    for (size_t index = 0; index < logdbtest::kSegmentSizes[segment]; ++index) {
      report.set_op(FailReport::WRITE_ENTRY);
      db->WriteEntry(logdbtest::kKeys[index + offset],
                     logdbtest::kEntries[index + offset]);
      // For now we operate under the assumption that a failed file op is fatal,
      // so this assertion helps us catch missed file op failures.
      // If FileDB ever starts doing anything more clever, then this test
      // should be changed to account for self-healing.
      assert(!db->Failed());
      report.set_index(report.index() + 1);
    }
    report.set_op(FailReport::MAKE_SEGMENT);
    db->MakeSegment();
    assert(!db->Failed());
    report.set_op(FailReport::WRITE_SEGMENT_AND_INFO);
    db->WriteSegmentAndInfo(logdbtest::kSegmentInfos[segment]);
    assert(!db->Failed());
    report.set_segment(report.segment() + 1);
  }
}

static void CheckLog(FileDB *db, size_t logged_segments,
                     size_t pending_entries) {
  bstring result;

  assert(db->SegmentCount() == logged_segments);
  assert(db->PendingLogSize() == pending_entries);

  std::set<bstring> expected_segment;
  std::set<bstring> logged_segment;
  size_t segment, offset, index;
  for (segment = 0, offset = 0; segment < logged_segments;
       offset += logdbtest::kSegmentSizes[segment++]) {
    expected_segment.clear();
    logged_segment.clear();
    for (index = 0; index < logdbtest::kSegmentSizes[segment]; ++index) {
      assert(db->LookupEntry(segment, index, &result) == LogDB::LOGGED);
      expected_segment.insert(logdbtest::kEntries[offset + index]);
      logged_segment.insert(result);
    }
    assert(db->LookupSegmentInfo(segment, &result) == LogDB::LOGGED);
    assert(result == logdbtest::kSegmentInfos[segment]);
    assert(db->LookupEntry(segment, index, &result) == LogDB::NOT_FOUND);
    assert(expected_segment == logged_segment);
  }

  // We are allowed to lose pending entries, but we try not to.
  for (index = 0; index < pending_entries; ++index) {
    assert(db->LookupEntry(logdbtest::kKeys[offset + index],
                           LogDB::ANY, &result) == LogDB::PENDING);
    assert(result == logdbtest::kEntries[offset + index]);
  }

  // If we have a pending segment, then it must be complete.
  if (db->HasPendingSegment()) {
    expected_segment.clear();
    logged_segment.clear();
    for (index = 0; index < logdbtest::kSegmentSizes[logged_segments];
         ++index) {
      assert(db->PendingSegmentEntry(index, &result) == LogDB::PENDING);
      expected_segment.insert(logdbtest::kEntries[offset + index]);
      logged_segment.insert(result);
    }
    assert(db->PendingSegmentEntry(index, &result) == LogDB::NOT_FOUND);
    assert(expected_segment == logged_segment);
  }
}

static void Fail(std::string tmp_dir, unsigned fail_point, bool crash) {
  std::string faildb_dir(tmp_dir + "/" + kWorkingDir);
  int ret = mkdir(faildb_dir.c_str(), 0700);
  assert(ret == 0);

  FailDB faildb(tmp_dir, 5, fail_point, crash);
  MakeLog(&faildb);
  // If we reached here, the fail point was larger than the number of file ops:
  // we cycled through all file ops without failure.
  exit(42);
}

static void Resume(const std::string &tmp_dir) {
  FailReport report = ReadReport(tmp_dir);
  if (report.op() == FailReport::NO_FAIL)
    return;

  FileDB filedb(tmp_dir + "/" + kWorkingDir, 5);
  filedb.Init();
  size_t logged_segments = report.segment();
  size_t pending_entries = report.index();
  // FIXME: we should also assume that WriteEntry() may complete on resume.
  // If we don't have a pending segment, then the write must be complete.
  if (report.op() == FailReport::WRITE_SEGMENT_AND_INFO &&
      !filedb.HasPendingSegment()) {
    ++logged_segments;
    pending_entries = 0;
  }
  // Check that the logged segments and pending entries are intact.
  // TODO: also check that we can continue where we left off.
  CheckLog(&filedb, logged_segments, pending_entries);
}

// cmd fail failpoint [crash|fail]
// cmd resume
int main(int argc, char **argv) {
  assert(argc >= 3);
  std::string tmp_dir(argv[1]);

  if (strcmp(argv[2], "fail") == 0) {
    assert(argc == 5);

    int fail_point = atoi(argv[3]);
    assert(fail_point >= 0);

    if (strcmp(argv[4], "crash") == 0) {
      Fail(tmp_dir, fail_point, true);
    }
    else {
      assert(strcmp(argv[4], "fail") == 0);
      Fail(tmp_dir, fail_point, false);
    }
  } else {
    assert(argc == 3);
    assert(strcmp(argv[2], "resume") == 0);
    Resume(tmp_dir);
  }
}
