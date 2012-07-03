#include <assert.h>
#include <map>

#include "../include/types.h"
#include "../merkletree/LogRecord.h"
#include "../merkletree/LogVerifier.h"
#include "cache.h"


LogSegmentCheckpointCache::LogSegmentCheckpointCache(
    const std::vector<bstring> &cache) {
  std::vector<bstring>::const_iterator it;
  for (it = cache.begin(); it != cache.end(); ++it) {
    LogSegmentCheckpoint checkpoint;

    // Tolerate no cache errors, for now.
    assert(checkpoint.Deserialize(*it));
    // Tolerate duplicates, but do not allow mismatches.
    assert(Insert(checkpoint) == LogSegmentCheckpointCache::NEW ||
           LogSegmentCheckpointCache::CACHED);
  }
}

std::vector<bstring> LogSegmentCheckpointCache::WriteCache() const {
  std::vector<bstring> result;
  Cache::const_iterator it;
  for (it = cache_.begin(); it != cache_.end(); ++it) {
    result.push_back(it->second.Serialize());
  }
  return result;
}

LogSegmentCheckpointCache::CacheReply
LogSegmentCheckpointCache::Insert(const LogSegmentCheckpoint &checkpoint) {
    std::pair<Cache::iterator, bool> inserted =
        cache_.insert(Cache::value_type(checkpoint.sequence_number,
                                        checkpoint));
    if (inserted.second)
      return LogSegmentCheckpointCache::NEW;
    else if (LogVerifier::LogSegmentCheckpointConsistency(
        inserted.first->second, checkpoint) == LogVerifier::VERIFY_OK)
      return LogSegmentCheckpointCache::CACHED;
    else return LogSegmentCheckpointCache::MISMATCH;
  }
