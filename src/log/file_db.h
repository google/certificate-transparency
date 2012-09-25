/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef CERTIFICATE_DB_H
#define CERTIFICATE_DB_H
#include <map>
#include <set>
#include <stdint.h>
#include <vector>

#include "ct.pb.h"
#include "database.h"
#include "types.h"

class FileStorage;

// Database interface that stores certificates and tree head
// signatures in the filesystem.
class FileDB : public Database {
 public:
  // Reference implementation: reads the entire database on boot
  // and builds an in-memory index.
  // Writes to the underlying FileStorage are atomic (assuming underlying
  // file system operations such as 'rename' are atomic) which should
  // guarantee full recoverability from crashes/power failures.
  // The tree head database uses 6-byte primary keys corresponding to the
  // 6 lower bytes of the (unique) timestamp, so the storage depth of
  // the FileDB should be set up accordingly. For example, a storage depth
  // of 8 buckets tree head updates within about 1 minute
  // (timestamps xxxxxxxx0000 - xxxxxxxxFFFF) to the same directory.
  // Takes ownership of |cert_storage| and |tree_storage|.
  FileDB(FileStorage *cert_storage, FileStorage *tree_storage);
  ~FileDB();

  static const size_t kTimestampBytesIndexed;

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


  virtual WriteResult WriteTreeHead(const ct::SignedTreeHead &sth);

  virtual LookupResult LatestTreeHead(ct::SignedTreeHead *result) const;

 private:
  void BuildIndex();
  std::set<bstring> pending_keys_;
  std::map<uint64_t, bstring> sequence_map_;
  FileStorage *cert_storage_;
  // Store all tree heads, but currently only support looking up the latest one.
  // Other necessary lookup indices (by tree size, by timestamp range?) TBD.
  FileStorage *tree_storage_;
  uint64_t latest_tree_timestamp_;
  // The same as a bstring;
  bstring latest_timestamp_key_;
};
#endif
