#include <assert.h>
#include <map>
#include <string>

#include "../log/log_verifier.h"
#include "cache.h"

SignedCertificateHashCache::SignedCertificateHashCache(
    const std::vector<std::string> &cache) {
  std::vector<std::string>::const_iterator it;
  for (it = cache.begin(); it != cache.end(); ++it) {
    SignedCertificateHash sch;

    // Tolerate no cache errors, for now.
    sch.ParseFromString(*it);
    // Tolerate duplicates, but do not allow mismatches.
    CacheReply reply = Insert(sch);
    assert(reply == SignedCertificateHashCache::NEW ||
           reply == SignedCertificateHashCache::CACHED);
  }
}

std::vector<std::string> SignedCertificateHashCache::WriteCache() const {
  std::vector<std::string> result;
  Cache::const_iterator it;
  for (it = cache_.begin(); it != cache_.end(); ++it) {
    std::string entry;
    it->second.SerializeToString(&entry);
    result.push_back(entry);
  }
  return result;
}

SignedCertificateHashCache::CacheReply
SignedCertificateHashCache::Insert(const SignedCertificateHash &sch) {
  // TODO: key by hash.
  std::pair<Cache::iterator, bool> inserted =
      cache_.insert(Cache::value_type(sch.entry().leaf_certificate(), sch));
  if (inserted.second)
    return SignedCertificateHashCache::NEW;
  else if (LogVerifier::VerifySCHConsistency(inserted.first->second, sch) ==
           LogVerifier::VERIFY_OK)
    return SignedCertificateHashCache::CACHED;
  else return SignedCertificateHashCache::MISMATCH;
}
