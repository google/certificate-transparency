/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef CERTIFICATE_DB_H
#define CERTIFICATE_DB_H
#include <map>
#include <set>
#include <stdint.h>
#include <vector>

#include "log/database.h"
#include "proto/ct.pb.h"

class FileStorage;

// Database interface that stores certificates and tree head
// signatures in the filesystem.
template <class Logged> class FileDB : public Database<Logged> {
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
  virtual typename Database<Logged>::WriteResult
  CreatePendingEntry_(const Logged &logged);

  virtual typename Database<Logged>::WriteResult
  AssignSequenceNumber(const std::string &hash,
                       uint64_t sequence_number);

  virtual typename Database<Logged>::LookupResult
  LookupByHash(const std::string &hash) const;

  virtual typename Database<Logged>::LookupResult
  LookupByHash(const std::string &hash, Logged *result) const;

  virtual typename Database<Logged>::LookupResult
  LookupByIndex(uint64_t sequence_number, Logged *result) const;

  virtual std::set<std::string> PendingHashes() const;

  virtual typename Database<Logged>::WriteResult
  WriteTreeHead_(const ct::SignedTreeHead &sth);

  virtual typename Database<Logged>::LookupResult
  LatestTreeHead(ct::SignedTreeHead *result) const;

 private:
  void BuildIndex();
  std::set<std::string> pending_hashes_;
  std::map<uint64_t, std::string> sequence_map_;
  FileStorage *cert_storage_;
  // Store all tree heads, but currently only support looking up the latest one.
  // Other necessary lookup indices (by tree size, by timestamp range?) TBD.
  FileStorage *tree_storage_;
  uint64_t latest_tree_timestamp_;
  // The same as a string;
  std::string latest_timestamp_key_;
};
#endif
