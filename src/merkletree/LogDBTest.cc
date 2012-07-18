#include <gtest/gtest.h>
#include <set>
#include <stddef.h>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>

#include "../include/types.h"
#include "LogDB.h"
#include "LogDBTestConstants.h"

namespace {

// For FileDB.
const char *kFileBase="/tmp/ct/a";
const unsigned kStorageDepth=5;

// Set up files for the LogDB.
template <class T> void SetupDB() {}

template <class T> LogDB *CreateLogDB() {
  return new T();
}

// Clean up files written on disk.
// Does not delete the LogDB object itself.
template <class T> void DestroyDB() {}

template <> void SetupDB<FileDB>() {
  ASSERT_EQ(mkdir(kFileBase, 0777), 0);
}

template <> LogDB *CreateLogDB<FileDB>() {
  FileDB *file_db = new FileDB(kFileBase, kStorageDepth);
  file_db->Init();
  return file_db;
}

template <> void DestroyDB<FileDB>() {
  std::string system_cmd = "rm -r " + std::string(kFileBase);
  ASSERT_EQ(system(system_cmd.c_str()), 0);
}

template <class T>
class LogDBTest : public ::testing::Test {
 protected:
  LogDBTest()
      : db_(NULL) {}

  void SetUp() {
    SetupDB<T>();
    db_ = CreateLogDB<T>();
    ASSERT_TRUE(db_ != NULL);
  }

  // Insert all the entries in a segment; get back a segment set.
  std::set<bstring> InsertSegmentEntries(size_t segment, size_t offset) {
    bstring key, data, result;
    std::set<bstring> segment_set;
    EXPECT_EQ(db_->PendingLogSize(), 0U);
    for (size_t index = 0; index < logdbtest::kSegmentSizes[segment]; ++index) {
      // Insert the entries of this segment.
      key = logdbtest::kKeys[offset + index];
      data = logdbtest::kEntries[offset + index];
      EXPECT_EQ(db_->WriteEntry(key, data), LogDB::NEW);
      segment_set.insert(data);
      // Check that the entry is listed as pending...
      EXPECT_EQ(db_->LookupEntry(key, LogDB::ANY, &result), LogDB::PENDING);
      EXPECT_EQ(result, data);
      result.clear();
      EXPECT_EQ(db_->LookupEntry(key, LogDB::PENDING_ONLY, &result),
                LogDB::PENDING);
      EXPECT_EQ(result, data);
      result.clear();
      EXPECT_EQ(db_->LookupEntry(key, LogDB::LOGGED_ONLY, &result),
                LogDB::PENDING);
      EXPECT_TRUE(result.empty());
      // ... but not listed in a segment.
      EXPECT_EQ(db_->LookupEntry(segment, index, NULL), LogDB::NOT_FOUND);
      // Try to enter the data again.
      EXPECT_EQ(db_->WriteEntry(key, data), LogDB::PENDING);
      // Check that the pending log size is correct.
      EXPECT_EQ(db_->PendingLogSize(), index + 1);
    }
    return segment_set;
  }

  // Test reading the pending segment.
  std::vector<bstring> CheckPendingSegment(size_t segment, size_t offset) {
    bstring key, data, result;
    std::vector<bstring> pending_segment;
    size_t index;
    const size_t pending_size = db_->PendingLogSize();
    for (index = 0; index < logdbtest::kSegmentSizes[segment]; ++index) {
      key = logdbtest::kKeys[offset + index];
      data = logdbtest::kEntries[offset + index];
      EXPECT_EQ(db_->LookupEntry(key, LogDB::ANY, &result), LogDB::PENDING);
      EXPECT_EQ(result, data);
      EXPECT_EQ(db_->LookupEntry(segment, index, NULL), LogDB::NOT_FOUND);
      EXPECT_EQ(db_->PendingSegmentEntry(index, &result), LogDB::PENDING);
      pending_segment.push_back(result);
      // Try to enter the data again.
      EXPECT_EQ(db_->WriteEntry(key, data), LogDB::PENDING);
      // Check that the pending log size is still correct.
      EXPECT_EQ(db_->PendingLogSize(), pending_size);
    }
    // Check that the pending segment contains no more entries.
    EXPECT_EQ(db_->PendingSegmentEntry(index, NULL), LogDB::NOT_FOUND);
    return pending_segment;
  }

  // Test reading a logged segment.
  std::vector<bstring> CheckLoggedSegment(size_t segment, size_t offset) {
    bstring key, data, result;
    std::vector<bstring> logged_segment;
    size_t index;
    for (index = 0; index < logdbtest::kSegmentSizes[segment]; ++index) {
      key = logdbtest::kKeys[offset + index];
      data = logdbtest::kEntries[offset + index];
      result.clear();
      EXPECT_EQ(db_->LookupEntry(key, LogDB::ANY, &result), LogDB::LOGGED);
      EXPECT_EQ(result, data);
      result.clear();
      EXPECT_EQ(db_->LookupEntry(key, LogDB::LOGGED_ONLY, &result),
                LogDB::LOGGED);
      EXPECT_EQ(result, data);
      result.clear();
      EXPECT_EQ(db_->LookupEntry(key, LogDB::PENDING_ONLY, &result),
                LogDB::LOGGED);
      EXPECT_TRUE(result.empty());
      EXPECT_EQ(db_->LookupEntry(segment, index, &result), LogDB::LOGGED);
      logged_segment.push_back(result);
      // Try to insert the entry again.
      EXPECT_EQ(db_->WriteEntry(key, data), LogDB::LOGGED);
    }
    // Check that the segment contains no more entries.
    EXPECT_EQ(db_->LookupEntry(segment, index, NULL), LogDB::NOT_FOUND);
    return logged_segment;
  }

  void TearDown() {
    DestroyDB<T>();
  }

  ~LogDBTest() {
    delete db_;
  }

  LogDB *db_;
};

// Check the full log after everything's been logged.
void CheckLog(LogDB *db) {
  EXPECT_EQ(db->PendingLogSize(), 0U);
  EXPECT_FALSE(db->HasPendingSegment());
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
      EXPECT_EQ(db->LookupEntry(segment, index, &result), LogDB::LOGGED);
      expected_segment.insert(logdbtest::kEntries[offset + index]);
      logged_segment.insert(result);
    }
    EXPECT_EQ(db->LookupEntry(segment, index, NULL), LogDB::NOT_FOUND);
    EXPECT_EQ(expected_segment, logged_segment);
  }
  EXPECT_EQ(db->LookupEntry(segment, index, NULL), LogDB::NOT_FOUND);

  // Look up by keys.
  for (index = 0; index < logdbtest::kLogSize; ++index) {
    key = logdbtest::kKeys[index];
    data = logdbtest::kEntries[index];
    EXPECT_EQ(db->LookupEntry(key, LogDB::ANY, &result), LogDB::LOGGED);
    EXPECT_EQ(result, data);
  }
}

typedef ::testing::Types<MemoryDB, FileDB> LogDBImplementations;

TYPED_TEST_CASE(LogDBTest, LogDBImplementations);

// Tests

// Test building the log segment by segment.
TYPED_TEST(LogDBTest, BuildSegments) {
  EXPECT_EQ(this->db_->PendingLogSize(), 0U);
  EXPECT_EQ(this->db_->LookupEntry(0, 0, NULL), LogDB::NOT_FOUND);
  EXPECT_FALSE(this->db_->HasPendingSegment());

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
    segment_set = this->InsertSegmentEntries(segment, offset);

    // Make the segment.
    this->db_->MakeSegment();
    EXPECT_TRUE(this->db_->HasPendingSegment());
    EXPECT_EQ(this->db_->PendingSegmentNumber(), segment);
    EXPECT_EQ(this->db_->SegmentCount(), segment);
    EXPECT_EQ(this->db_->PendingSegmentSize(), logdbtest::kSegmentSizes[segment]);
    EXPECT_EQ(this->db_->PendingLogSize(), logdbtest::kSegmentSizes[segment]);

    // Check the pending segment.
    pending_segment = this->CheckPendingSegment(segment, offset);

    // The two sets should be the same, modulo ordering.
    EXPECT_EQ(segment_set, std::set<bstring>(pending_segment.begin(),
                                             pending_segment.end()));
    // Finalize the segment.
    EXPECT_EQ(this->db_->LookupSegmentInfo(segment, NULL), LogDB::NOT_FOUND);
    this->db_->WriteSegmentAndInfo(logdbtest::kSegmentInfos[segment]);
    EXPECT_EQ(this->db_->SegmentCount(), segment + 1);
    EXPECT_FALSE(this->db_->HasPendingSegment());
    EXPECT_EQ(this->db_->PendingLogSize(), 0U);

    // Look up the segment info.
    bstring result;
    EXPECT_EQ(this->db_->LookupSegmentInfo(segment, &result), LogDB::LOGGED);
    EXPECT_EQ(result, logdbtest::kSegmentInfos[segment]);

    // Check the logged segment.
    logged_segment = this->CheckLoggedSegment(segment, offset);

    // Check that the ordering didn't change.
    EXPECT_EQ(logged_segment, pending_segment);
  }

  // Finally, check once more that the log is consistent.
  CheckLog(this->db_);
}

// Test that we can add new pending entries while there is a pending segment
// that has not been finalized (i.e., we are waiting for segment info).
TYPED_TEST(LogDBTest, Interleave) {
  EXPECT_EQ(this->db_->PendingLogSize(), 0U);
  EXPECT_EQ(this->db_->LookupEntry(0, 0, NULL), LogDB::NOT_FOUND);
  EXPECT_FALSE(this->db_->HasPendingSegment());

  // The initial set, unordered.
  std::set<bstring> segment_set;
  // The segment, ordered as the DB constructed it.
  std::vector<bstring> pending_segment;
  // The logged segment, ordered.
  std::vector<bstring> logged_segment;

  // Insert the entries in the first segment.
  segment_set = this->InsertSegmentEntries(0, 0);

  // Make the segment, but do not finalize it.
  this->db_->MakeSegment();
  EXPECT_TRUE(this->db_->HasPendingSegment());
  EXPECT_EQ(this->db_->PendingSegmentNumber(), 0U);
  EXPECT_EQ(this->db_->PendingSegmentSize(), logdbtest::kSegmentSizes[0]);
  EXPECT_EQ(this->db_->PendingLogSize(), logdbtest::kSegmentSizes[0]);

  pending_segment = this->CheckPendingSegment(0, 0);
  EXPECT_EQ(segment_set, std::set<bstring>(pending_segment.begin(),
                                           pending_segment.end()));

  // Now insert another pending entry.
  size_t index = logdbtest::kSegmentSizes[0];
  bstring iKey = logdbtest::kKeys[index];
  bstring iData = logdbtest::kEntries[index];
  EXPECT_EQ(this->db_->WriteEntry(iKey, iData), LogDB::NEW);
  // Check that the entry is listed as pending...
  bstring result;
  EXPECT_EQ(this->db_->LookupEntry(iKey, LogDB::ANY, &result), LogDB::PENDING);
  EXPECT_EQ(result, iData);

  EXPECT_TRUE(this->db_->HasPendingSegment());
  EXPECT_EQ(this->db_->PendingSegmentNumber(), 0U);
  EXPECT_EQ(this->db_->PendingSegmentSize(), logdbtest::kSegmentSizes[0]);
  // Check that the pending log has grown by one.
  EXPECT_EQ(this->db_->PendingLogSize(), logdbtest::kSegmentSizes[0] + 1);

  // Check that the pending segment is still correct.
  pending_segment = this->CheckPendingSegment(0, 0);
  EXPECT_EQ(segment_set, std::set<bstring>(pending_segment.begin(),
                                           pending_segment.end()));

  // Finalize the segment.
  this->db_->WriteSegmentAndInfo(logdbtest::kSegmentInfos[0]);
  EXPECT_EQ(this->db_->SegmentCount(), 1U);
  EXPECT_FALSE(this->db_->HasPendingSegment());
  EXPECT_EQ(this->db_->PendingLogSize(), 1U);

  // Check that the logged segment is correct.
  logged_segment = this->CheckLoggedSegment(0, 0);
  EXPECT_EQ(logged_segment, pending_segment);

  // Check that the interleaved entry is still pending.
  EXPECT_EQ(this->db_->LookupEntry(iKey, LogDB::ANY, &result), LogDB::PENDING);
  EXPECT_EQ(result, iData);
}

class ResumeFileDBTest : public LogDBTest<FileDB> {
};

TEST_F(ResumeFileDBTest, Resume) {
 // Create the log.
  for (size_t segment = 0, offset = 0; segment < logdbtest::kNumberOfSegments;
       offset += logdbtest::kSegmentSizes[segment++]) {
    this->InsertSegmentEntries(segment, offset);
    this->db_->MakeSegment();
    this->db_->WriteSegmentAndInfo(logdbtest::kSegmentInfos[segment]);
  }
  // Check the log.
  CheckLog(this->db_);

  // Resume from disk.
  FileDB db2(kFileBase, kStorageDepth);
  db2.Init();
  // Check that all is good.
  CheckLog(&db2);
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
