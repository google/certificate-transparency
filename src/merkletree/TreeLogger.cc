#include <string>
#include <utility>
#include <vector>

#include <assert.h>
#include <stddef.h>

#include "LogDB.h"
#include "MerkleTree.h"
#include "SerialHasher.h"
#include "TreeLogger.h"

TreeLogger::TreeLogger(LogDB *db) : db_(db),
				    segment_info_(new Sha256Hasher()) {
  logsegments_.push_back(new MerkleTree(new Sha256Hasher()));
}

TreeLogger::~TreeLogger() {
  delete db_;
  for (std::vector<MerkleTree*>::iterator it = logsegments_.begin();
       it < logsegments_.end(); ++it)
    delete *it;
}

LogDB::Status TreeLogger::QueueEntry(const std::string &data,
                                     std::string *key) {
  // First check whether the entry already exists.
  key->assign(logsegments_.back()->LeafHash(data));
  assert(!key->empty());
  LogDB::Status status = db_->WriteEntry(*key, data);

  switch(status) {
    case(LogDB::LOGGED):
    case(LogDB::PENDING):
      break;
    case(LogDB::NEW):
      // Work the data into the tree.
      logsegments_.back()->AddLeaf(data);
      break;
    default:
      assert(false);
  }
  return status;
}

LogDB::Status TreeLogger::EntryInfo(size_t index,
                                    LogDB::Lookup type,
                                    std::string *result) {
  return db_->LookupEntry(index, type, result);
}

LogDB::Status TreeLogger::EntryInfo(size_t segment, size_t index,
                                    LogDB::Lookup type,
                                    std::string *result) {
  return db_->LookupEntry(segment, index, type, result);
}

LogDB::Status TreeLogger::EntryInfo(const std::string &key,
                                    LogDB::Lookup type,
                                    std::string *result) {
  return db_->LookupEntry(key, type, result);
}

LogDB::Status TreeLogger::SegmentInfo(size_t index,
                                      std::string *result) {
  return db_->LookupSegmentInfo(index, result);
}

void TreeLogger::LogSegment() {
  std::string root = logsegments_.back()->CurrentRoot();
  assert(!root.empty());
  segment_info_.AddLeaf(root);

  root = segment_info_.CurrentRoot();
  assert(!root.empty());
  // Simply log the segment root as segment info, for now.
  db_->WriteSegmentInfo(root);
  // Start a new segment.
  logsegments_.push_back(new MerkleTree(new Sha256Hasher()));
}
