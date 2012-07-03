#include <iostream>
#include <set>
#include <string>

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "../include/types.h"
#include "LogDB.h"
#include "LogDBTestConstants.h"

// Helper test functions.

// Insert all the entries in a segment; get back a segment set.
static std::set<bstring> InsertSegmentEntries(LogDB *db, size_t segment,
                                                  size_t offset) {
  bstring key, data, result;
  std::set<bstring> segment_set;
  assert(db->PendingLogSize() == 0);
  for (size_t index = 0; index < logdbtest::kSegmentSizes[segment]; ++index) {
    // Insert the entries of this segment.
    key = logdbtest::kKeys[offset + index];
    data = logdbtest::kEntries[offset + index];
    assert(db->WriteEntry(key, data) == LogDB::NEW);
    segment_set.insert(data);
    // Check that the entry is listed as pending...
    assert(db->LookupEntry(key, LogDB::ANY, &result) == LogDB::PENDING);
    assert(result == data);
    result.clear();
    assert(db->LookupEntry(key, LogDB::PENDING_ONLY, &result) ==
           LogDB::PENDING);
    assert(result == data);
    result.clear();
    assert(db->LookupEntry(key, LogDB::LOGGED_ONLY, &result) ==
           LogDB::PENDING);
    assert(result.empty());
    // ... but not listed in a segment.
    assert(db->LookupEntry(segment, index, NULL) == LogDB::NOT_FOUND);
    // Try to enter the data again.
    assert(db->WriteEntry(key, data) == LogDB::PENDING);
    // Check that the pending log size is correct.
    assert(db->PendingLogSize() == index + 1);
  }
  return segment_set;
}

// Test reading the pending segment.
static std::vector<bstring> CheckPendingSegment(LogDB *db, size_t segment,
                                                    size_t offset) {
  bstring key, data, result;
  std::vector<bstring> pending_segment;
  size_t index;
  const size_t pending_size = db->PendingLogSize();
  for (index = 0; index < logdbtest::kSegmentSizes[segment]; ++index) {
    key = logdbtest::kKeys[offset + index];
    data = logdbtest::kEntries[offset + index];
    assert(db->LookupEntry(key, LogDB::ANY, &result) == LogDB::PENDING);
    assert(result == data);
    assert(db->LookupEntry(segment, index, NULL) == LogDB::NOT_FOUND);
    assert(db->PendingSegmentEntry(index, &result) == LogDB::PENDING);
    pending_segment.push_back(result);
    // Try to enter the data again.
    assert(db->WriteEntry(key, data) == LogDB::PENDING);
    // Check that the pending log size is still correct.
    assert(db->PendingLogSize() == pending_size);
  }
  // Check that the pending segment contains no more entries.
  assert(db->PendingSegmentEntry(index, NULL) == LogDB::NOT_FOUND);
  return pending_segment;
}

// Test reading a logged segment.
static std::vector<bstring> CheckLoggedSegment(LogDB *db, size_t segment,
                                                   size_t offset) {
  bstring key, data, result;
  std::vector<bstring> logged_segment;
  size_t index;
  for (index = 0; index < logdbtest::kSegmentSizes[segment]; ++index) {
    key = logdbtest::kKeys[offset + index];
    data = logdbtest::kEntries[offset + index];
    result.clear();
    assert(db->LookupEntry(key, LogDB::ANY, &result) == LogDB::LOGGED);
    assert(result == data);
    result.clear();
    assert(db->LookupEntry(key, LogDB::LOGGED_ONLY, &result) ==
           LogDB::LOGGED);
    assert(result == data);
    result.clear();
    assert(db->LookupEntry(key, LogDB::PENDING_ONLY, &result) ==
           LogDB::LOGGED);
    assert(result.empty());
    assert(db->LookupEntry(segment, index, &result) == LogDB::LOGGED);
    logged_segment.push_back(result);
    // Try to insert the entry again.
    assert(db->WriteEntry(key, data) == LogDB::LOGGED);
  }
  // Check that the segment contains no more entries.
  assert(db->LookupEntry(segment, index, static_cast<bstring*>(NULL)) == LogDB::NOT_FOUND);
  return logged_segment;
}

// Check the full log after everything's been logged.
void CheckLog(LogDB *db) {
  assert(db->PendingLogSize() == 0);
  assert(!db->HasPendingSegment());
  size_t segment, index = 0, offset;
  bstring key, data, result;
  std::set<bstring> expected_segment;
  std::set<bstring> logged_segment;

  // Look up by indices.
  for (segment = 0, offset = 0; segment < logdbtest::kNumberOfSegments;
       offset += logdbtest::kSegmentSizes[segment++]) {
    expected_segment.clear();
    logged_segment.clear();
    for (index = 0; index < logdbtest::kSegmentSizes[segment]; ++index) {
      assert(db->LookupEntry(segment, index, &result) == LogDB::LOGGED);
      expected_segment.insert(logdbtest::kEntries[offset + index]);
      logged_segment.insert(result);
    }
    assert(db->LookupEntry(segment, index, NULL) == LogDB::NOT_FOUND);
    assert(expected_segment == logged_segment);
  }
  assert(db->LookupEntry(segment, index, NULL) == LogDB::NOT_FOUND);

  // Look up by keys.
  for (index = 0; index < logdbtest::kLogSize; ++index) {
    key = logdbtest::kKeys[index];
    data = logdbtest::kEntries[index];
    assert(db->LookupEntry(key, LogDB::ANY, &result) == LogDB::LOGGED);
    assert(result == data);
  }
}

// Tests

// Test building the log segment by segment.
static void LogDBTest(LogDB *db) {
  assert(db->PendingLogSize() == 0);
  assert(db->LookupEntry(0, 0, NULL) == LogDB::NOT_FOUND);
  assert(!db->HasPendingSegment());

  // The initial set, unordered.
  std::set<bstring> segment_set;
  // The segment, ordered as the DB constructed it.
  std::vector<bstring> pending_segment;
  // The logged segment, ordered.
  std::vector<bstring> logged_segment;
  for (size_t segment = 0, offset = 0; segment < logdbtest::kNumberOfSegments;
       offset += logdbtest::kSegmentSizes[segment++]) {
    pending_segment.clear();
    logged_segment.clear();

    // Insert the entries in this segment.
    segment_set = InsertSegmentEntries(db, segment, offset);

    // Make the segment.
    db->MakeSegment();
    assert(db->HasPendingSegment());
    assert(db->PendingSegmentNumber() == segment);
    assert(db->SegmentCount() == segment);
    assert(db->PendingSegmentSize() == logdbtest::kSegmentSizes[segment]);
    assert(db->PendingLogSize() == logdbtest::kSegmentSizes[segment]);

    // Check the pending segment.
    pending_segment = CheckPendingSegment(db, segment, offset);

    // The two sets should be the same, modulo ordering.
    assert(segment_set == std::set<bstring>(pending_segment.begin(),
                                            pending_segment.end()));
    // Finalize the segment.
    assert(db->LookupSegmentInfo(segment, NULL) == LogDB::NOT_FOUND);
    db->WriteSegmentAndInfo(logdbtest::kSegmentInfos[segment]);
    assert(db->SegmentCount() == segment + 1);
    assert(!db->HasPendingSegment());
    assert(db->PendingLogSize() == 0);

    // Look up the segment info.
    bstring result;
    assert(db->LookupSegmentInfo(segment, &result) == LogDB::LOGGED);
    assert(result == logdbtest::kSegmentInfos[segment]);

    // Check the logged segment.
    logged_segment = CheckLoggedSegment(db, segment, offset);

    // Check that the ordering didn't change.
    assert(logged_segment == pending_segment);
  }

  // Finally, check once more that the log is consistent.
  CheckLog(db);
}

// Test that we can add new pending entries while there is a pending segment
// that has not been finalized (i.e., we are waiting for segment info).
static void InterleaveTest(LogDB *db) {
  assert(db->PendingLogSize() == 0);
  assert(db->LookupEntry(0, 0, NULL) == LogDB::NOT_FOUND);
  assert(!db->HasPendingSegment());

  // The initial set, unordered.
  std::set<bstring> segment_set;
  // The segment, ordered as the DB constructed it.
  std::vector<bstring> pending_segment;
  // The logged segment, ordered.
  std::vector<bstring> logged_segment;

  // Insert the entries in the first segment.
  segment_set = InsertSegmentEntries(db, 0, 0);

  // Make the segment, but do not finalize it.
  db->MakeSegment();
  assert(db->HasPendingSegment());
  assert(db->PendingSegmentNumber() == 0);
  assert(db->PendingSegmentSize() == logdbtest::kSegmentSizes[0]);
  assert(db->PendingLogSize() == logdbtest::kSegmentSizes[0]);

  pending_segment = CheckPendingSegment(db, 0, 0);
  assert(segment_set == std::set<bstring>(pending_segment.begin(),
                                          pending_segment.end()));

  // Now insert another pending entry.
  size_t index = logdbtest::kSegmentSizes[0];
  bstring iKey = logdbtest::kKeys[index];
  bstring iData = logdbtest::kEntries[index];
  assert(db->WriteEntry(iKey, iData) == LogDB::NEW);
  // Check that the entry is listed as pending...
  bstring result;
  assert(db->LookupEntry(iKey, LogDB::ANY, &result) == LogDB::PENDING);
  assert(result == iData);

  assert(db->HasPendingSegment());
  assert(db->PendingSegmentNumber() == 0);
  assert(db->PendingSegmentSize() == logdbtest::kSegmentSizes[0]);
  // Check that the pending log has grown by one.
  assert(db->PendingLogSize() == logdbtest::kSegmentSizes[0] + 1);

  // Check that the pending segment is still correct.
  pending_segment = CheckPendingSegment(db, 0, 0);
  assert(segment_set == std::set<bstring>(pending_segment.begin(),
                                              pending_segment.end()));

  // Finalize the segment.
  db->WriteSegmentAndInfo(logdbtest::kSegmentInfos[0]);
  assert(db->SegmentCount() == 1);
  assert(!db->HasPendingSegment());
  assert(db->PendingLogSize() == 1);

  // Check that the logged segment is correct.
  logged_segment = CheckLoggedSegment(db, 0, 0);
  assert(logged_segment == pending_segment);

  // Check that the interleaved entry is still pending.
  assert(db->LookupEntry(iKey, LogDB::ANY, &result) == LogDB::PENDING);
  assert(result == iData);
}

static void MemoryDBTest() {
  MemoryDB db, db2;
  LogDBTest(&db);
  InterleaveTest(&db2);
}

static void FileDBTest() {
  // Create a new directory for testing.
  assert(mkdir("/tmp/ct/a", 0777) == 0);
  FileDB db("/tmp/ct/a", 5);
  db.Init();
  LogDBTest(&db);
  assert(system("rm -r /tmp/ct/a") == 0);
  assert(mkdir("/tmp/ct/a", 0777) == 0);
  FileDB db2("/tmp/ct/a", 5);
  db2.Init();
  InterleaveTest(&db2);
  assert(system("rm -r /tmp/ct/a") == 0);
}

static void FileDBResumeTest() {
  // Create a new directory for testing.
  assert(mkdir("/tmp/ct/a", 0777) == 0);
  // Resume the full log.
  FileDB db("/tmp/ct/a", 5);
  db.Init();
  LogDBTest(&db);
  FileDB db2("/tmp/ct/a", 5);
  db2.Init();
  CheckLog(&db2);
  assert(system("rm -r /tmp/ct/a") == 0);
}

int main(int, char**) {
  std::cout << "Testing MemoryDB\n";
  MemoryDBTest();
  std::cout << "PASS\n";
  std::cout << "Testing FileDB\n";
  FileDBTest();
  std::cout << "PASS\n";
  std::cout << "Testing FileDB resumption\n";
  FileDBResumeTest();
  std::cout << "PASS\n";
  return 0;
}
