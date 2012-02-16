#include <map>
#include <string>
#include <utility>
#include <vector>

#include <assert.h>
#include <stddef.h>

#include "LogDB.h"

MemoryDB::MemoryDB() {
  segment_offsets_.push_back(0);
}

LogDB::Status MemoryDB::WriteEntry(const std::string &key,
                                   const std::string &data) {
  // Check for duplicates.
  std::pair<index::iterator,bool> inserted =
      index_.insert(std::pair<std::string,size_t>(key, entries_.size()));
  if (inserted.second) {
    entries_.push_back(data);
    return LogDB::NEW;
  }
  if (inserted.first->second >= segment_offsets_.back())
    return LogDB::PENDING;
  return LogDB::LOGGED;
}

void MemoryDB::WriteSegmentInfo(const std::string &data) {
  segment_offsets_.push_back(entries_.size());
  segment_infos_.push_back(data);
}

LogDB::Status MemoryDB::LookupEntry(size_t index, LogDB::Lookup type,
                                    std::string *result) const {
  if (index >= entries_.size())
    return LogDB::NOT_FOUND;

  if (index >= segment_offsets_.back()) {
    if (result != NULL && (type == LogDB::ANY || type == LogDB::PENDING_ONLY))
      result->assign(entries_[index]);
    return LogDB::PENDING;
  }
  if (result != NULL && (type == LogDB::ANY || type == LogDB::LOGGED_ONLY))
    result->assign(entries_[index]);
  return LogDB::LOGGED;
}

LogDB::Status MemoryDB::LookupEntry(size_t segment, size_t index,
                                    LogDB::Lookup type,
                                    std::string *result) const {
  if (segment >= segment_offsets_.size())
    return LogDB::NOT_FOUND;
  size_t loc = segment_offsets_[segment] + index;
  return LookupEntry(loc, type, result);
}

LogDB::Status MemoryDB::LookupEntry(const std::string &key, LogDB::Lookup type,
                                    std::string *result) const {
  std::map<std::string,size_t>::const_iterator it = index_.find(key);
  if (it == index_.end())
    return LogDB::NOT_FOUND;
  return LookupEntry(it->second, type, result);
}

LogDB::Status MemoryDB::LookupSegmentInfo(size_t index,
                                          std::string *result) const {
  if (index > segment_infos_.size())
    return LogDB::NOT_FOUND;
  if (index == segment_infos_.size())
    return LogDB::PENDING;
  if (result != NULL)
    result->assign(segment_infos_[index]);
  return LogDB::LOGGED;
}
