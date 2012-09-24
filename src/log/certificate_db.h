#ifndef CERTIFICATE_DB_H
#define CERTIFICATE_DB_H
#include <map>
#include <set>
#include <stdint.h>
#include <vector>

#include "ct.pb.h"
#include "database.h"
#include "types.h"

class FileDB;

// Database interface for storing certificates and tree head signatures.
// TODO(ekasper): separate an abstract base class so that we can make
// the underlying DB pluggable.
class CertificateDB : public Database {
 public:
  // Reference implementation: reads the entire database on boot
  // and builds an in-memory index.
  // Writes to the underlying FileDB are atomic (assuming underlying
  // file system operations such as 'rename' are atomic) which should
  // guarantee full recoverability from crashes/power failures.
  // Takes ownership of |cert_db|.
  CertificateDB(FileDB *cert_db);
  ~CertificateDB();

  // Implement abstract functions, see database.h for comments.
  virtual WriteResult
  CreatePendingCertificateEntry(const bstring &pending_key,
                                const ct::SignedCertificateTimestamp &sct);
  virtual WriteResult
  AssignCertificateSequenceNumber(const bstring &pending_key,
				  uint64_t sequence_number);
  virtual LookupResult
  LookupCertificateEntry(const bstring &certificate_key,
                         uint64_t *sequence_number,
                         ct::SignedCertificateTimestamp *result) const;
  virtual LookupResult
  LookupCertificateEntry(uint64_t sequence_number,
                         ct::SignedCertificateTimestamp *result) const;
  virtual std::set<bstring> PendingKeys() const;

 private:
  void BuildIndex();
  std::set<bstring> pending_keys_;
  std::map<uint64_t, bstring> sequence_map_;
  FileDB *cert_db_;
};
#endif
