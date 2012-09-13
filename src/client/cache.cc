#include <assert.h>
#include <map>
#include <string>

#include "cache.h"
#include "ct.pb.h"
#include "log_verifier.h"

using ct::SignedCertificateTimestamp;

SCTCache::SCTCache(
    const std::vector<std::string> &cache) {
  std::vector<std::string>::const_iterator it;
  for (it = cache.begin(); it != cache.end(); ++it) {
    SignedCertificateTimestamp sct;

    // Tolerate no cache errors, for now.
    sct.ParseFromString(*it);
    // Tolerate duplicates, but do not allow mismatches.
    CacheReply reply = Insert(sct);
    assert(reply == SCTCache::NEW ||
           reply == SCTCache::CACHED);
  }
}

std::vector<std::string> SCTCache::WriteCache() const {
  std::vector<std::string> result;
  Cache::const_iterator it;
  for (it = cache_.begin(); it != cache_.end(); ++it) {
    std::string entry;
    it->second.SerializeToString(&entry);
    result.push_back(entry);
  }
  return result;
}

SCTCache::CacheReply
SCTCache::Insert(const SignedCertificateTimestamp &sct) {
  // TODO: key by hash.
  std::pair<Cache::iterator, bool> inserted =
      cache_.insert(Cache::value_type(sct.entry().leaf_certificate(), sct));
  if (inserted.second)
    return SCTCache::NEW;
  else if (LogVerifier::VerifySCTConsistency(inserted.first->second, sct) ==
           LogVerifier::VERIFY_OK)
    return SCTCache::CACHED;
  else return SCTCache::MISMATCH;
}
