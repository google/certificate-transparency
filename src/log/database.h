/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef DATABASE_H
#define DATABASE_H

#include <glog/logging.h>
#include <set>

#include "ct.pb.h"

class Database {
 public:
  enum WriteResult {
    OK,
    // Create failed, certificate hash is primary key and must exist.
    MISSING_CERTIFICATE_HASH,
    // Create failed, an entry with this hash already exists.
    DUPLICATE_CERTIFICATE_HASH,
    // Update failed, entry already has a sequence number.
    ENTRY_ALREADY_LOGGED,
    // Update failed, entry does not exist.
    ENTRY_NOT_FOUND,
    // Another entry has this sequence number already.
    // We only report this if the entry is pending (i.e., ENTRY_NOT_FOUND
    // and ENTRY_ALREADY_LOGGED did not happen).
    SEQUENCE_NUMBER_ALREADY_IN_USE,
    // Timestamp is primary key, it must exist and be unique,
    DUPLICATE_TREE_HEAD_TIMESTAMP,
    MISSING_TREE_HEAD_TIMESTAMP,
  };

  enum LookupResult {
    LOOKUP_OK,
    NOT_FOUND,
  };

  virtual ~Database() {}

  virtual bool Transactional() const { return false; }

  virtual void BeginTransaction() {
    DLOG(FATAL) << "Transactions not supported";
  }

  virtual void EndTransaction() {
    DLOG(FATAL) << "Transactions not supported";
  }

  // Attempt to create a new entry. Fail if no certificate hash is given,
  // or an entry with this hash already exists.
  // The entry remains PENDING until a sequence number has been assigned,
  // after which its status changes to LOGGED.
  WriteResult
  CreatePendingCertificateEntry(const ct::LoggedCertificate &logged_cert) {
    assert(!logged_cert.has_sequence_number());
    if (!logged_cert.has_certificate_sha256_hash())
      return MISSING_CERTIFICATE_HASH;
    return CreatePendingCertificateEntry_(logged_cert);
  }
  virtual WriteResult
  CreatePendingCertificateEntry_(const ct::LoggedCertificate &logged_cert) = 0;

  // Attempt to add a sequence number to the LoggedCertificate, thereby
  // removing it from the list of pending entries.
  // Fail if the entry does not exist, already has a sequence number,
  // or an entry with this sequence number already exists (i.e.,
  // |sequence_number| is a secondary key.
  virtual WriteResult
  AssignCertificateSequenceNumber(const std::string &pending_hash,
				  uint64_t sequence_number) = 0;

  // Look up certificate by hash. If the entry exists, and result is not NULL,
  // write the result. If the entry is not logged return PENDING.
  virtual LookupResult
  LookupCertificateByHash(const std::string &certificate_sha256_hash,
                          ct::LoggedCertificate *result) const = 0;

  // Look up certificate by sequence number.
  virtual LookupResult
  LookupCertificateByIndex(uint64_t sequence_number,
                           ct::LoggedCertificate *result) const = 0;

  // List the hashes of all pending entries, i.e. all entries without a
  // sequence number.
  virtual std::set<std::string> PendingHashes() const = 0;

  // Attempt to write a tree head. Fails only if a tree head with this timestamp
  // already exists (i.e., |timestamp| is primary key). Does not check that
  // the timestamp is newer than previous entries.
  WriteResult WriteTreeHead(const ct::SignedTreeHead &sth) {
    if (!sth.has_timestamp())
      return MISSING_TREE_HEAD_TIMESTAMP;
    return WriteTreeHead_(sth);
  }
  virtual WriteResult WriteTreeHead_(const ct::SignedTreeHead &sth) = 0;

  // Return the tree head with the freshest timestamp.
  virtual LookupResult LatestTreeHead(ct::SignedTreeHead *result) const = 0;
};

#endif  // ndef DATABASE_H
