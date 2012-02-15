#ifndef TREELOGGER_H
#define TREELOGGER_H
#include <string>
#include <utility>
#include <vector>

#include <stddef.h>

#include "LogDB.h"
#include "MerkleTree.h"

class TreeLogger {
 public:
  // TODO: make the hash function pluggable.
  TreeLogger(LogDB *db);
  ~TreeLogger();

  // Add an entry to the current, pending segment if it doesn't already exist.
  // Writes a key (= leaf hash) that can be used to look up the data
  // and its associated signatures and audit proofs later on.
  LogDB::Status QueueEntry(const std::string &data, std::string *key);

  // Get the status of a data record corresponding to an absolute index.
  // Write the data record if result is not NULL. Only write pending entries
  // if write_pending is true.
  LogDB::Status EntryInfo(size_t index, LogDB::Lookup type,
                          std::string *result);

  // Get the data record corresponding to an index in a segment.
  LogDB::Status EntryInfo(size_t segment, size_t index, LogDB::Lookup type,
                          std::string *result);

  // Get the data record corresponding to a leaf hash.
  LogDB::Status EntryInfo(const std::string &key, LogDB::Lookup type,
                          std::string *result);

  // Get the status of a segment by its index.
  // Write the segment info if the result is not NULL.
  LogDB::Status SegmentInfo(size_t index, std::string *result);

  size_t SegmentCount() const {
    return db_->SegmentCount();
  }

  size_t LogSize(LogDB::Lookup type) const {
    return db_->LogSize(type);
  }

  // Finalize the current segment, write it to the DB and start a new one.
  void LogSegment();

 private:
  LogDB *db_;

  // Keep all trees in memory for now.
  std::vector<MerkleTree*> logsegments_;
  MerkleTree segment_info_;
};
#endif
