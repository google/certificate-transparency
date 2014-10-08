#ifndef TREE_SIGNER_H
#define TREE_SIGNER_H

#include <stdint.h>

#include "merkletree/compact_merkle_tree.h"
#include "proto/ct.pb.h"

template <class Logged>
class Database;
class LogSigner;

// Signer for appending new entries to the log.
// This is the single authority that assigns sequence numbers to new entries,
// timestamps and signs tree heads. The signer process assumes there are
// no other signers during its lifetime -- when it discovers the database has
// received tree updates it has not written, it does not try to recover,
// but rather reports an error.
template <class Logged>
class TreeSigner {
 public:
  // Does not take ownership of |signer|.
  TreeSigner(Database<Logged>* db, LogSigner* signer);

  enum UpdateResult {
    OK,
    // The database is inconsistent with our view.
    DB_ERROR,
  };

  // Latest Tree Head timestamp;
  uint64_t LastUpdateTime() const;

  // Simplest update mechanism: take all pending entries and append
  // (in random order) to the tree. Checks that the update it writes
  // to the database is consistent with the latest STH.
  UpdateResult UpdateTree();

  // Latest Tree Head (does not build a new tree, just retrieves the
  // result of the most recent build).
  const ct::SignedTreeHead& LatestSTH() const {
    return latest_tree_head_;
  }

 private:
  void BuildTree();
  bool Append(const Logged& logged);
  void AppendToTree(const Logged& logged_cert);
  void TimestampAndSign(uint64_t min_timestamp, ct::SignedTreeHead* sth);

  Database<Logged>* const db_;
  LogSigner* const signer_;
  // TODO(ekasper): it's a waste for the signer to keep the entire tree in
  // memory. Implement a compact version of the tree that runs in "restricted"
  // mode, i.e., only remembers O(log n) nodes and cannot answer queries
  // about audit paths or previous snapshots.
  CompactMerkleTree cert_tree_;
  ct::SignedTreeHead latest_tree_head_;
};
#endif
