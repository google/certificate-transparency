#include "cache.h"
#include "../merkletree/LogRecord.h"
#include "../merkletree/LogVerifier.h"

#include <map>
#include <string>

#include <assert.h>

LogSegmentCheckpointCache::LogSegmentCheckpointCache(
    const std::vector<bstring> &cache) {
  std::vector<bstring>::const_iterator it;
  for (it = cache.begin(); it != cache.end(); ++it) {
    LogSegmentCheckpoint checkpoint;
    // I will sort this casting mess out, I promise.
    bstring b = *it;

    // Tolerate no cache errors, for now.
    assert(checkpoint.Deserialize(*(reinterpret_cast<const std::string*>(&b))));
    // Tolerate duplicates, but do not allow mismatches.
    assert(Insert(checkpoint) == LogSegmentCheckpointCache::NEW ||
           LogSegmentCheckpointCache::CACHED);
  }
}

std::vector<bstring> LogSegmentCheckpointCache::WriteCache() const {
  std::vector<bstring> result;
  Cache::const_iterator it;
  for (it = cache_.begin(); it != cache_.end(); ++it) {
    std::string r = it->second.Serialize();
    result.push_back(*(reinterpret_cast<bstring*>(&r)));
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
