/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef CERTIFICATE_DB_H
#define CERTIFICATE_DB_H

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdint.h>
#include <vector>

#include "base/macros.h"
#include "log/database.h"
#include "proto/ct.pb.h"

namespace cert_trans {
class FileStorage;
}

// Database interface that stores certificates and tree head
// signatures in the filesystem.
template <class Logged>
class FileDB : public Database<Logged> {
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
  FileDB(cert_trans::FileStorage* cert_storage,
         cert_trans::FileStorage* tree_storage);
  ~FileDB();

  static const size_t kTimestampBytesIndexed;

  // Implement abstract functions, see database.h for comments.
  typename Database<Logged>::WriteResult CreateSequencedEntry_(
      const Logged& logged) override;

  typename Database<Logged>::LookupResult LookupByHash(
      const std::string& hash, Logged* result) const override;

  typename Database<Logged>::LookupResult LookupByIndex(
      int64_t sequence_number, Logged* result) const override;

  typename Database<Logged>::WriteResult WriteTreeHead_(
      const ct::SignedTreeHead& sth) override;

  typename Database<Logged>::LookupResult LatestTreeHead(
      ct::SignedTreeHead* result) const override;

  int64_t TreeSize() const override;

  void AddNotifySTHCallback(
      const typename Database<Logged>::NotifySTHCallback* callback) override;

  void RemoveNotifySTHCallback(
      const typename Database<Logged>::NotifySTHCallback* callback) override;

 private:
  void BuildIndex();
  typename Database<Logged>::LookupResult LatestTreeHeadNoLock(
      ct::SignedTreeHead* result) const;

  const std::unique_ptr<cert_trans::FileStorage> cert_storage_;
  // Store all tree heads, but currently only support looking up the latest
  // one.
  // Other necessary lookup indices (by tree size, by timestamp range?) TBD.
  const std::unique_ptr<cert_trans::FileStorage> tree_storage_;

  mutable std::mutex lock_;
  std::map<int64_t, std::string> sequence_map_;
  uint64_t latest_tree_timestamp_;
  // The same as a string;
  std::string latest_timestamp_key_;
  cert_trans::DatabaseNotifierHelper callbacks_;

  DISALLOW_COPY_AND_ASSIGN(FileDB);
};
#endif
