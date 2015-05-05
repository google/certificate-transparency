#ifndef CERTIFICATE_LEVELDB_DB_H
#define CERTIFICATE_LEVELDB_DB_H

#include <leveldb/db.h>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdint.h>
#include <unordered_map>
#include <vector>

#include "base/macros.h"
#include "log/database.h"
#include "proto/ct.pb.h"
#include "util/statusor.h"

namespace cert_trans {
class FileStorage;
}

template <class Logged>
class LevelDB : public Database<Logged> {
 public:
  static const size_t kTimestampBytesIndexed;

  explicit LevelDB(const std::string& dbfile);
  ~LevelDB() = default;

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

  void InitializeNode(const std::string& node_id) override;

  typename Database<Logged>::LookupResult NodeId(
      std::string* node_id) override;

 private:
  void BuildIndex();
  typename Database<Logged>::LookupResult LatestTreeHeadNoLock(
      ct::SignedTreeHead* result) const;
  void InsertEntryMapping(int64_t sequence_number, const std::string& hash);

  mutable std::mutex lock_;
  std::unique_ptr<leveldb::DB> db_;

  int64_t contiguous_size_;
  std::unordered_map<std::string, int64_t> id_by_hash_;

  // This is a mapping of the non-contiguous entries of the log (which
  // can happen while it is being fetched). When entries here become
  // contiguous with the beginning of the tree, they are removed.
  std::set<int64_t> sparse_entries_;

  uint64_t latest_tree_timestamp_;
  std::string latest_timestamp_key_;
  cert_trans::DatabaseNotifierHelper callbacks_;

  DISALLOW_COPY_AND_ASSIGN(LevelDB);
};
#endif  // CERTIFICATE_LEVELDB_DB_H
