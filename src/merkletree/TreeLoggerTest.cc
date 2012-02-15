#include <assert.h>
#include <iostream>
#include <stddef.h>
#include <string>

#include "LogDB.h"
#include "TreeLogger.h"

namespace {

void MemoryLoggerTest() {
  TreeLogger treelogger(new MemoryDB());
  std::string key0, key1, key2, key3, value0, value1, value2, value3,
      segment0, segment1;
  assert(treelogger.QueueEntry("Unicorn", &key0) == LogDB::NEW);
  assert(treelogger.QueueEntry("Alice", &key1) == LogDB::NEW);

  // Count with and without pending entries.
  assert(treelogger.LogSize(LogDB::LOGGED_ONLY) == 0);
  assert(treelogger.LogSize(LogDB::PENDING_ONLY) == 2);
  assert(treelogger.LogSize(LogDB::ANY) == 2);

  // Try to enter a duplicate.
  assert(treelogger.QueueEntry("Unicorn", &key2) == LogDB::PENDING);
  assert(key0 == key2);
  assert(treelogger.LogSize(LogDB::LOGGED_ONLY) == 0);
  assert(treelogger.LogSize(LogDB::PENDING_ONLY) == 2);
  assert(treelogger.LogSize(LogDB::ANY) == 2);

  // Look up pending entries.
  assert(treelogger.SegmentCount() == 0);
  assert(treelogger.EntryInfo(0, LogDB::ANY, &value0) == LogDB::PENDING);
  assert(value0 == "Unicorn");
  assert(treelogger.EntryInfo(0, 1, LogDB::ANY, NULL) == LogDB::PENDING);
  assert(treelogger.EntryInfo(key1, LogDB::LOGGED_ONLY, &value1)
         == LogDB::PENDING);
  assert(value1.empty());
  assert(treelogger.EntryInfo(key1, LogDB::PENDING_ONLY, &value1)
         == LogDB::PENDING);
  assert(value1 == "Alice");

  // Look up missing entries.
  assert(treelogger.EntryInfo(2, LogDB::ANY, NULL) == LogDB::NOT_FOUND);
  assert(treelogger.EntryInfo(1, 0, LogDB::ANY, &value2) == LogDB::NOT_FOUND);
  assert(value2.empty());

  // Look up missing segment info.
  assert(treelogger.SegmentInfo(0, NULL) == LogDB::PENDING);
  assert(treelogger.SegmentInfo(1, NULL) == LogDB::NOT_FOUND);
  assert(treelogger.SegmentInfo(0, &segment0) == LogDB::PENDING);
  assert(segment0.empty());

  // Log the first segment.
  treelogger.LogSegment();
  assert(treelogger.LogSize(LogDB::LOGGED_ONLY) == 2);
  assert(treelogger.LogSize(LogDB::PENDING_ONLY) == 0);
  assert(treelogger.LogSize(LogDB::ANY) == 2);
  assert(treelogger.SegmentCount() == 1);
  assert(treelogger.SegmentInfo(0, &segment0) == LogDB::LOGGED);
  assert(!segment0.empty());

  value0.clear();
  value1.clear();
  value2.clear();

  // Look up logged entries.
  assert(treelogger.EntryInfo(0, LogDB::LOGGED_ONLY, &value0) == LogDB::LOGGED);
  assert(value0 == "Unicorn");
  assert(treelogger.EntryInfo(0, 1, LogDB::ANY, &value1) == LogDB::LOGGED);
  assert(value1 == "Alice");
  assert(treelogger.EntryInfo(key0, LogDB::PENDING_ONLY, &value2)
         == LogDB::LOGGED);
  assert(value2.empty());
  assert(treelogger.EntryInfo(key0, LogDB::ANY, &value2) == LogDB::LOGGED);
  assert(value2 == "Unicorn");

  // Look up missing entries.
  assert(treelogger.EntryInfo(0, 2, LogDB::ANY, NULL) == LogDB::NOT_FOUND);
  assert(treelogger.EntryInfo(1, 0, LogDB::ANY, NULL) == LogDB::NOT_FOUND);
  assert(treelogger.EntryInfo(key3, LogDB::ANY, NULL) == LogDB::NOT_FOUND);
  key3 = "RogueKey";
  assert(treelogger.EntryInfo(key3, LogDB::ANY, &value3) == LogDB::NOT_FOUND);
  assert(value3.empty());

  // Queue another entry and look it up.
  assert(treelogger.QueueEntry("Banana", &key3) == LogDB::NEW);
  assert(treelogger.SegmentCount() == 1);
  assert(treelogger.EntryInfo(2, LogDB::PENDING_ONLY, &value3)
         == LogDB::PENDING);
  assert(value3 == "Banana");
  assert(treelogger.EntryInfo(1, 0, LogDB::ANY, NULL) == LogDB::PENDING);
  value3.clear();
  assert(treelogger.EntryInfo(key3, LogDB::ANY, &value3) == LogDB::PENDING);
  assert(value3 == "Banana");

  // Log the segment.
  assert(treelogger.LogSize(LogDB::LOGGED_ONLY) == 2);
  assert(treelogger.LogSize(LogDB::PENDING_ONLY) == 1);
  assert(treelogger.LogSize(LogDB::ANY) == 3);
  treelogger.LogSegment();
  assert(treelogger.LogSize(LogDB::LOGGED_ONLY) == 3);
  assert(treelogger.LogSize(LogDB::PENDING_ONLY) == 0);
  assert(treelogger.LogSize(LogDB::ANY) == 3);
  assert(treelogger.SegmentCount() == 2);
  assert(treelogger.SegmentInfo(1, &segment1) == LogDB::LOGGED);
  // TODO: test tree manipulation to ensure segments are computed correctly.
  assert(segment0 != segment1);

  // Look up the logged entry.
  assert(treelogger.EntryInfo(2, LogDB::ANY, NULL) == LogDB::LOGGED);
  value3.clear();
  assert(treelogger.EntryInfo(1, 0, LogDB::LOGGED_ONLY, &value3)
         == LogDB::LOGGED);
  assert(value3 == "Banana");
  value3.clear();
  assert(treelogger.EntryInfo(key3, LogDB::ANY, &value3) == LogDB::LOGGED);
  assert(value3 == "Banana");

  // More missing data.
  assert(treelogger.EntryInfo(1, 1, LogDB::ANY, NULL) == LogDB::NOT_FOUND);

  assert(treelogger.SegmentInfo(2, NULL) == LogDB::PENDING);
  assert(treelogger.SegmentInfo(3, NULL) == LogDB::NOT_FOUND);
}

} // namespace

int main(int, char**) {
  std::cout << "Testing MemoryLogger\n";
  MemoryLoggerTest();
  std::cout << "PASS\n";
  return 0;
}
