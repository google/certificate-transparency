#ifndef LOG_LOOKUP_H
#define LOG_LOOKUP_H

#include <stdint.h>

#include "merkletree/merkle_tree.h"

class Database;

// Lookups into the database. Read-only, so could also be a mirror.
// Keeps the entire Merkle Tree in memory to serve audit proofs.
class LogLookup {
 public:
  explicit LogLookup(const Database *db);
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

  // Look up by timestamp + SHA256-hash of the certificate.
  LookupResult CertificateAuditProof(uint64_t timestamp,
                                     const std::string &certificate_hash,
                                     ct::MerkleAuditProof *proof);

 private:
  std::string LeafHash(const ct::LoggedCertificate &logged_cert);

  const Database *db_;
  MerkleTree cert_tree_;
  ct::SignedTreeHead latest_tree_head_;
};
#endif
