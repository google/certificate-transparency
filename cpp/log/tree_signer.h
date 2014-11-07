#ifndef TREE_SIGNER_H
#define TREE_SIGNER_H

#include <chrono>
#include <stdint.h>

#include "log/consistent_store.h"
#include "merkletree/compact_merkle_tree.h"
#include "proto/ct.pb.h"


namespace util {
class Status;
}  // namespace util

template <class Logged>
class Database;
class LogSigner;


namespace cert_trans {


// Signer for appending new entries to the log.
// This is the single authority that assigns sequence numbers to new entries,
// timestamps and signs tree heads. The signer process assumes there are
// no other signers during its lifetime -- when it discovers the database has
// received tree updates it has not written, it does not try to recover,
// but rather reports an error.
template <class Logged>
class TreeSigner {
 public:
  // No transfer of ownership for params.
  TreeSigner(const std::chrono::duration<double>& guard_window,
             Database<Logged>* db,
             cert_trans::ConsistentStore<Logged>* consistent_store,
             LogSigner* signer);

  enum UpdateResult {
    OK,
    // The database is inconsistent with our view.
    DB_ERROR,
  };

  // Latest Tree Head timestamp;
  uint64_t LastUpdateTime() const;

  util::Status SequenceNewEntries();

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
  util::Status HandlePreviouslySequencedEntries(
      std::vector<cert_trans::EntryHandle<Logged>>* pending_entries) const;
  void BuildTree();
  bool Append(const Logged& logged);
  void AppendToTree(const Logged& logged_cert);
  void TimestampAndSign(uint64_t min_timestamp, ct::SignedTreeHead* sth);

  std::chrono::duration<double> guard_window_;
  Database<Logged>* const db_;
  cert_trans::ConsistentStore<Logged>* const consistent_store_;
  LogSigner* const signer_;
  // TODO(ekasper): it's a waste for the signer to keep the entire tree in
  // memory. Implement a compact version of the tree that runs in "restricted"
  // mode, i.e., only remembers O(log n) nodes and cannot answer queries
  // about audit paths or previous snapshots.
  CompactMerkleTree cert_tree_;
  ct::SignedTreeHead latest_tree_head_;
};


}  // namespace cert_trans

#endif
