#ifndef CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_H_
#define CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_H_

#include <memory>
#include <stdint.h>
#include <vector>

#include "base/macros.h"
#include "log/consistent_store.h"
#include "proto/ct.pb.h"
#include "util/status.h"
#include "util/sync_etcd.h"

namespace cert_trans {


template <class Logged>
class EtcdConsistentStore : public ConsistentStore<Logged> {
 public:
  EtcdConsistentStore(SyncEtcdClient* client, const std::string& root,
                      const std::string& node_id);

  uint64_t NextAvailableSequenceNumber() const override;

  util::Status SetServingSTH(const ct::SignedTreeHead& new_sth) override;

  util::Status AddPendingEntry(Logged* entry) override;

  util::Status GetPendingEntryForHash(
      const std::string& hash, EntryHandle<Logged>* entry) const override;

  util::Status GetPendingEntries(
      std::vector<EntryHandle<Logged>>* entries) const override;

  util::Status GetSequencedEntries(
      std::vector<EntryHandle<Logged>>* entries) const override;

  util::Status GetSequencedEntry(const uint64_t sequence_number,
                                 EntryHandle<Logged>* entry) const override;

  util::Status AssignSequenceNumber(const uint64_t sequence_number,
                                    EntryHandle<Logged>* entry) override;

  util::Status SetClusterNodeState(const ct::ClusterNodeState& state) override;

 private:
  template <class T>
  util::Status GetEntry(const std::string& path, EntryHandle<T>* entry) const;

  template <class T>
  util::Status GetAllEntriesInDir(const std::string& dir,
                                  std::vector<EntryHandle<T>>* entries) const;

  template <class T>
  util::Status UpdateEntry(const std::string& path, EntryHandle<T>* entry);

  template <class T>
  util::Status CreateEntry(const std::string& path, EntryHandle<T>* entry);

  template <class T>
  util::Status ForceSetEntry(const std::string& path, EntryHandle<T>* entry);

  std::string GetUnsequencedPath(const Logged& unseq) const;

  std::string GetUnsequencedPath(const std::string& hash) const;

  std::string GetSequencedPath(uint64_t seq) const;

  std::string GetNodePath(const std::string& node_id) const;

  std::string GetFullPath(const std::string& key) const;

  SyncEtcdClient* const client_;
  const std::string root_;
  const std::string node_id_;

  DISALLOW_COPY_AND_ASSIGN(EtcdConsistentStore);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_H_
