#ifndef LOG_LOOKUP_H
#define LOG_LOOKUP_H

#include <stdint.h>

#include "merkle_tree.h"

class Database;

// Lookups into the database. Read-only, so could also be a mirror.
// Keeps the entire Merkle Tree in memory to serve audit proofs.
class LogLookup {
 public:
  LogLookup(const Database *db);
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
    DB_ERROR,
  };

  // Look up by timestamp + SHA256-hash of the certificate.
  LookupResult CertificateAuditProof(uint64_t timestamp,
                                     const bstring &certificate_hash,
                                     ct::MerkleAuditProof *proof);

 private:
  bstring LeafHash(const ct::SignedCertificateTimestamp &sct);

  const Database *db_;
  MerkleTree cert_tree_;
  ct::SignedTreeHead latest_tree_head_;
};
#endif
