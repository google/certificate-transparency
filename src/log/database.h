#ifndef DATABASE_H
#define DATABASE_H

#include <set>

#include "ct.pb.h"
#include "types.h"

class Database {
 public:
  enum WriteResult {
    OK,
    // Create failed.
    ENTRY_ALREADY_PENDING,
    // Create or update failed, entry already has a sequence number.
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
    LOGGED,
    PENDING,
    NOT_FOUND,
  };

  // Attempt to create a new entry. Fail if no certificate key is given,
  // or an entry with this key already exists.
  // The entry remains PENDING until a sequence number has been assigned,
  // after which its status changes to LOGGED.
  virtual WriteResult
  CreatePendingCertificateEntry(const bstring &pending_key,
                                const ct::SignedCertificateTimestamp &sct) = 0;

  // Attempt to add a sequence number to the LoggedCertificate, thereby
  // removing it from the list of pending entries.
  // Fail if the entry does not exist, already has a sequence number,
  // or an entry with this sequence number already exists (i.e.,
  // |sequence_number| is a secondary key.
  virtual WriteResult
  AssignCertificateSequenceNumber(const bstring &pending_key,
				  uint64_t sequence_number) = 0;

  // Look up certificate by key. If the entry exists, and result is not NULL,
  // write the result. If the entry is logged, also write the sequence number
  // (else return PENDING).
  virtual LookupResult
  LookupCertificateEntry(const bstring &certificate_key,
                         uint64_t *sequence_number,
                         ct::SignedCertificateTimestamp *result) const = 0;

  // Look up certificate by key. If the entry exists, and result is not NULL,
  // write the result. If the entry is not logged return PENDING.
  LookupResult
  LookupCertificateEntry(const bstring &certificate_key,
                         ct::SignedCertificateTimestamp *result) const {
    return LookupCertificateEntry(certificate_key, NULL, result);
  }

  // Look up certificate by sequence number.
  virtual LookupResult
  LookupCertificateEntry(uint64_t sequence_number,
                         ct::SignedCertificateTimestamp *result) const = 0;

  // List the keys of all pending entries, i.e. all entries without a
  // sequence number.
  virtual std::set<bstring> PendingKeys() const = 0;

  // Attempt to write a tree head. Fails only if a tree head with this timestamp
  // already exists (i.e., |timestamp| is primary key). Does not check that
  // the timestamp is newer than previous entries.
  virtual WriteResult WriteTreeHead(const ct::SignedTreeHead &sth) = 0;

  // Return the tree head with the freshest timestamp.
  virtual LookupResult LatestTreeHead(ct::SignedTreeHead *result) const = 0;
};

#endif  // ndef DATABASE_H
