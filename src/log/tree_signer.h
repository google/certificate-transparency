#ifndef TREE_SIGNER_H
#define TREE_SIGNER_H

#include <stdint.h>

#include "merkletree/merkle_tree.h"
#include "proto/ct.pb.h"

class Database;
class LogSigner;

// Signer for appending new entries to the log.
// This is the single authority that assigns sequence numbers to new entries,
// timestamps and signs tree heads. The signer process assumes there are
// no other signers during its lifetime -- when it discovers the database has
// received tree updates it has not written, it does not try to recover,
// but rather reports an error.
class TreeSigner {
 public:
  // Takes ownership of the signer.
  TreeSigner(Database *db, LogSigner *signer);
  ~TreeSigner();

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

 private:
  void BuildTree();
  bool AppendCertificate(const ct::LoggedCertificate &logged_cert);
  void AppendCertificateToTree(const ct::LoggedCertificate &logged_cert);
  void TimestampAndSign(uint64_t min_timestamp, ct::SignedTreeHead *sth);
  Database *db_;
  LogSigner *signer_;
  // TODO(ekasper): it's a waste for the signer to keep the entire tree in
  // memory. Implement a compact version of the tree that runs in "restricted"
  // mode, i.e., only remembers O(log n) nodes and cannot answer queries
  // about audit paths or previous snapshots.
  MerkleTree cert_tree_;
  ct::SignedTreeHead latest_tree_head_;
};
#endif
