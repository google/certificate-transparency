#ifndef CACHE_H
#define CACHE_H
#include <map>
#include <string>

#include "ct.h"
#include "ct.pb.h"

class SignedCertificateHashCache {
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

  SignedCertificateHashCache() {}
  explicit SignedCertificateHashCache(const std::vector<std::string> &cache);

  ~SignedCertificateHashCache() {}

  // Serialize the cache.
  std::vector<std::string> WriteCache() const;

  CacheReply Insert(const SignedCertificateHash &sch);

 private:
  typedef std::map<std::string, SignedCertificateHash> Cache;
  Cache cache_;
};
#endif
