/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef LOG_LOOKUP_H
#define LOG_LOOKUP_H

#include <map>
#include <stdint.h>
#include <string>

#include "merkletree/merkle_tree.h"
#include "proto/ct.pb.h"

template <class Logged> class Database;

// Lookups into the database. Read-only, so could also be a mirror.
// Keeps the entire Merkle Tree in memory to serve audit proofs.
template <class Logged> class LogLookup {
 public:
  explicit LogLookup(const Database<Logged> *db);
  ~LogLookup();

  enum UpdateResult {
    UPDATE_OK,
    // Also ok, but we found nothing new.
    NO_UPDATES_FOUND,
  };

  // Pick up latest tree changes from the database.
  UpdateResult Update();

  enum LookupResult {
    OK,
    NOT_FOUND,
  };

  // Look up by hash of the logged item.
  LookupResult AuditProof(const std::string &merkle_leaf_hash,
                          ct::MerkleAuditProof *proof);

  // Look up by hash of the logged item and tree_size
  LookupResult AuditProof(const std::string &merkle_leaf_hash,
                          size_t tree_size, ct::ShortMerkleAuditProof *proof);

  // Get a consitency proof between two tree heads
  std::vector<std::string> ConsistencyProof(size_t first, size_t second) {
    return cert_tree_.SnapshotConsistency(first, second);
  }

  // Get the |index|th log entry.
  LookupResult GetEntry(size_t index, Logged *result) {
    if (db_->LookupByIndex(index, result) != Database<Logged>::LOOKUP_OK)
      return NOT_FOUND;
    return OK;
  }

 private:
  std::string LeafHash(const Logged &logged);
  // We keep a hash -> index mapping in memory so that we can quickly serve
  // Merkle proofs without having to query the database at all.
  // Note that 32 bytes is an overkill and we can optimize this to use
  // a shorter prefix (possibly with a multimap).
  std::map<std::string, uint64_t> leaf_index_;

  const Database<Logged> *db_;
  MerkleTree cert_tree_;
  ct::SignedTreeHead latest_tree_head_;
};
#endif
