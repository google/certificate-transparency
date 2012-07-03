#include <fstream>
#include <set>
#include <string>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/types.h"
#include "../util/util.h"
#include "LogDB.h"
#include "LogDBTestConstants.h"

namespace {

enum FailedOp {
  INIT = 0,
  WRITE_ENTRY = 1,
  MAKE_SEGMENT = 2,
  WRITE_SEGMENT_AND_INFO = 3,
  NO_FAIL = 4,
};

struct FailReport {
  FailReport() : op(NO_FAIL), segment(0), index(0) {}
  FailedOp op;
  size_t segment;
  size_t index;
};

}  // namespace

static FailReport report;

static const char kWorkingDir[] = "/tmp/ct/fail";
static const char kReportFile[] = "/tmp/ct/fail/report";

static void MakeReport() {
  if (access(kWorkingDir, W_OK) < 0)
    return;
  bstring res = util::SerializeUint(report.op, 1);
  res.append(util::SerializeUint(report.segment, 4));
  res.append(util::SerializeUint(report.index, 4));
  std::ofstream report_file(kReportFile, std::ios::out | std::ios::trunc |
                            std::ios::binary);
  assert(report_file.good());
  report_file.write(reinterpret_cast<const char*>(res.data()), res.length());
  assert(report_file.good());
  report_file.close();
}

namespace {

// A class that behaves exactly like FileDB, except it counts file ops
// and fails at a specific point.
class FailDB : public FileDB {
 public:
  FailDB(const std::string &file_base, unsigned storage_depth,
         unsigned fail_point, bool crash)
      : FileDB(file_base, storage_depth),
        op_count_(0),
        fail_point_(fail_point),
        crash_(crash),
        failed_(false) {}

 bool Failed() const { return failed_; }

 private:
  int mkdir(const char *path, mode_t mode) {
    if (fail_point_ == op_count_++) {
      failed_ = true;
      MakeReport();
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
      MakeReport();
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
      MakeReport();
      if (crash_) {
        exit(0);
      } else {
        errno = EIO;
        return -1;
      }
    }
    return ::rename(old_name, new_name);
  }

  unsigned op_count_;
  unsigned fail_point_;
  bool crash_; // If true, crash on fail.
  bool failed_; // True if we have already failed.
};

}  // namespace

static FailReport ReadReport() {
  bstring result;
  bool read_success = util::ReadBinaryFile(kReportFile, &result);
  assert(read_success);
  assert(result.size() == 9);
  FailReport ret;
  ret.op = static_cast<FailedOp>(util::DeserializeUint(result.substr(0, 1)));
  ret.segment = util::DeserializeUint(result.substr(1, 4));
  ret.index = util::DeserializeUint(result.substr(5, 4));
  return ret;
}

// Returns true if no file ops failed; false otherwise.
static void MakeLog(FailDB *db) {
  report.op = INIT;
  db->Init();

  for (size_t segment = 0, offset = 0; segment < logdbtest::kNumberOfSegments;
       offset += logdbtest::kSegmentSizes[segment++]) {
    report.index = 0;
    for (size_t index = 0; index < logdbtest::kSegmentSizes[segment]; ++index) {
      report.op = WRITE_ENTRY;
      db->WriteEntry(logdbtest::kKeys[index + offset],
                     logdbtest::kEntries[index + offset]);
      // For now we operate under the assumption that a failed file op is fatal,
      // so this assertion helps us catch missed file op failures.
      // If FileDB ever starts doing anything more clever, then this test
      // should be changed to account for self-healing.
      assert(!db->Failed());
      ++report.index;
    }
    report.op = MAKE_SEGMENT;
    db->MakeSegment();
    assert(!db->Failed());
    report.op = WRITE_SEGMENT_AND_INFO;
    db->WriteSegmentAndInfo(logdbtest::kSegmentInfos[segment]);
    assert(!db->Failed());
    ++report.segment;
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

static void Clean() {
  std::string removedir = "rm -r " + std::string(kWorkingDir);
  assert(system(removedir.c_str()) == 0);
}

static void Fail(unsigned fail_point, bool crash) {
  FailDB faildb(kWorkingDir, 5, fail_point, crash);
  MakeLog(&faildb);
  // If we reached here, the fail point was larger than the number of file ops:
  // we cycled through all file ops without failure.
  Clean();
  exit(42);
}

static void Resume(const FailReport &report) {
  if (report.op == NO_FAIL)
    return;
  FileDB filedb(kWorkingDir, 5);
  filedb.Init();
  size_t logged_segments = report.segment;
  size_t pending_entries = report.index;
  // FIXME: we should also assume that WriteEntry() may complete on resume.
  // If we don't have a pending segment, then the write must be complete.
  if (report.op == WRITE_SEGMENT_AND_INFO && !filedb.HasPendingSegment()) {
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
  assert(argc >= 2);

  if (strcmp(argv[1], "fail") == 0) {
    assert(argc == 4);
    int fail_point = atoi(argv[2]);
    assert(fail_point >= 0);
    assert(mkdir(kWorkingDir, 0777) == 0);
    if (strcmp(argv[3], "crash") == 0) {
      Fail(fail_point, true);
    }
    else {
      assert(strcmp(argv[3], "fail") == 0);
      Fail(fail_point, false);
    }
  } else {
    assert(argc == 2);
    assert(strcmp(argv[1], "resume") == 0);
    FailReport rep = ReadReport();
    atexit(Clean);
    Resume(rep);
  }
}
