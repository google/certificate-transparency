#ifndef CACHE_H
#define CACHE_H
#include "../include/ct.h"
#include "../merkletree/LogRecord.h"

#include <map>
#include <string>

class LogSegmentCheckpointCache {
public:
  enum CacheReply {
    // A new entry.
    NEW,
    // Already cached.
    CACHED,
    // The checkpoint with this sequence number is already in cache,
    // but the rest of the data do not match. This is really bad,
    // and could indicate log misbehaviour.
    MISMATCH,
  };

  LogSegmentCheckpointCache() {}
  explicit LogSegmentCheckpointCache(const std::vector<bstring> &cache);

  ~LogSegmentCheckpointCache() {}

  // Serialize the cache.
  std::vector<bstring> WriteCache() const;

  CacheReply Insert(const LogSegmentCheckpoint &checkpoint);

 private:
  typedef std::map<size_t, LogSegmentCheckpoint> Cache;
  Cache cache_;
};
#endif
