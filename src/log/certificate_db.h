#ifndef CERTIFICATE_DB_H
#define CERTIFICATE_DB_H
#include <map>
#include <set>
#include <stdint.h>
#include <vector>

#include "ct.pb.h"
#include "types.h"

class FileDB;

// Database interface for storing certificates and tree head signatures.
// TODO(ekasper): separate an abstract base class so that we can make
// the underlying DB pluggable.
class CertificateDB {
 public:
  // Reference implementation: reads the entire database on boot
  // and builds an in-memory index.
  // Writes to the underlying FileDB are atomic (assuming underlying
  // file system operations such as 'rename' are atomic) which should
  // guarantee full recoverability from crashes/power failures.
  // Takes ownership of |cert_db|.
  CertificateDB(FileDB *cert_db);
  ~CertificateDB();

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
  WriteResult
  CreatePendingCertificateEntry(const bstring &pending_key,
                                const ct::SignedCertificateTimestamp &sct);

  // List the keys of all pending entries, i.e. all entries without a
  // sequence number.
  std::set<bstring> PendingKeys() const;

  // Attempt to add a sequence number to the LoggedCertificate, thereby
  // removing it from the list of pending entries.
  // Fail if the entry does not exist, already has a sequence number,
  // or an entry with this sequence number already exists (i.e.,
  // |sequence_number| is a secondary key.
  WriteResult AssignCertificateSequenceNumber(const bstring &pending_key,
                                              uint64_t sequence_number);

  // Look up certificate by key. If the entry exists, and result is not NULL,
  // write the result. If the entry is logged, also write the sequence number
  // (else return PENDING).
  LookupResult
  LookupCertificateEntry(const bstring &certificate_key,
                         ct::SignedCertificateTimestamp *result) const {
    return LookupCertificateEntry(certificate_key, NULL, result);
  }

  // Look up certificate by key. If the entry exists, and result is not NULL,
  // write the result. If the entry is logged, also write the sequence number
  // (else return PENDING).
  LookupResult
  LookupCertificateEntry(const bstring &certificate_key,
                         uint64_t *sequence_number,
                         ct::SignedCertificateTimestamp *result) const;

  // Look up certificate by sequence number.
  LookupResult
  LookupCertificateEntry(uint64_t sequence_number,
                         ct::SignedCertificateTimestamp *result) const;
 private:
  void BuildIndex();
  std::set<bstring> pending_keys_;
  std::map<uint64_t, bstring> sequence_map_;
  FileDB *cert_db_;
};
#endif
