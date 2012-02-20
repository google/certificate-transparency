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
  Location loc(segment_infos_.size(),
               entries_.size() - segment_offsets_.back());
  // LocationMap is a map of (key, Location) pairs.
  std::pair<LocationMap::iterator, bool> inserted =
      map_.insert(LocationMap::value_type(key, loc));
  if (inserted.second) {
    entries_.push_back(data);
    return LogDB::NEW;
  }
  if (inserted.first->second.segment_number == segment_infos_.size())
    return LogDB::PENDING;
  assert(inserted.first->second.segment_number < segment_infos_.size());
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
  LocationMap::const_iterator it = map_.find(key);
  if (it == map_.end())
    return LogDB::NOT_FOUND;
  return LookupEntry(it->second.segment_number, it->second.index_in_segment,
                     type, result);
}

LogDB::Status MemoryDB::EntryLocation(const std::string &key, size_t *segment,
                                      size_t *index) const {
  LocationMap::const_iterator it = map_.find(key);
  if (it == map_.end())
    return LogDB::NOT_FOUND;
  assert(segment != NULL && index != NULL);
  *segment = it->second.segment_number;
  *index = it->second.index_in_segment;
  if (*segment == segment_infos_.size())
    return LogDB::PENDING;
  assert(*segment < segment_infos_.size());
  return LogDB::LOGGED;
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
