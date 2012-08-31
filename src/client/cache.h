#ifndef CACHE_H
#define CACHE_H
#include <map>
#include <string>

#include "ct.h"
#include "ct.pb.h"

// Signed Certificate Timestamp cache.
class SCTCache {
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

  SCTCache() {}
  explicit SCTCache(const std::vector<std::string> &cache);

  ~SCTCache() {}

  // Serialize the cache.
  std::vector<std::string> WriteCache() const;

  CacheReply Insert(const SignedCertificateTimestamp &sct);

 private:
  typedef std::map<std::string, SignedCertificateTimestamp> Cache;
  Cache cache_;
};
#endif
