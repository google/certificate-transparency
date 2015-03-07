#ifndef CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_H_
#define CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_H_

#include <memory>
#include <mutex>
#include <stdint.h>
#include <vector>

#include "base/macros.h"
#include "log/consistent_store.h"
#include "proto/ct.pb.h"
#include "util/etcd.h"
#include "util/status.h"
#include "util/sync_task.h"

namespace cert_trans {

class MasterElection;


template <class Logged>
class EtcdConsistentStore : public ConsistentStore<Logged> {
 public:
  // No change of ownership for |client|, |executor| must continue to be valid
  // at least as long as this object is, and should not be the libevent::Base
  // used by |client|.
  EtcdConsistentStore(util::Executor* executor, EtcdClient* client,
                      const MasterElection* election, const std::string& root,
                      const std::string& node_id);

  virtual ~EtcdConsistentStore();

  util::StatusOr<int64_t> NextAvailableSequenceNumber() const override;

  util::Status SetServingSTH(const ct::SignedTreeHead& new_sth) override;

  util::StatusOr<ct::SignedTreeHead> GetServingSTH() const override;

  util::Status AddPendingEntry(Logged* entry) override;

  util::Status GetPendingEntryForHash(
      const std::string& hash, EntryHandle<Logged>* entry) const override;

  util::Status GetPendingEntries(
      std::vector<EntryHandle<Logged>>* entries) const override;

  util::Status GetSequencedEntries(
      std::vector<EntryHandle<Logged>>* entries) const override;

  util::Status GetSequencedEntry(const int64_t sequence_number,
                                 EntryHandle<Logged>* entry) const override;

  util::Status AssignSequenceNumber(const int64_t sequence_number,
                                    EntryHandle<Logged>* entry) override;

  util::StatusOr<ct::ClusterNodeState> GetClusterNodeState() const override;

  util::Status SetClusterNodeState(const ct::ClusterNodeState& state) override;

  void WatchServingSTH(
      const typename ConsistentStore<Logged>::ServingSTHCallback& cb,
      util::Task* task) override;

  void WatchClusterNodeStates(
      const typename ConsistentStore<Logged>::ClusterNodeStateCallback& cb,
      util::Task* task) override;

  void WatchClusterConfig(
      const typename ConsistentStore<Logged>::ClusterConfigCallback& cb,
      util::Task* task) override;

  util::Status SetClusterConfig(const ct::ClusterConfig& config) override;

  // Removes entries in /sequenced (and their corresponding entries in
  // /unsequened) with sequence numbers covered by the current serving STH.
  util::Status CleanupOldEntries() override;

 private:
  void WaitForServingSTHVersion(std::unique_lock<std::mutex>* lock,
                                const int version);

  template <class T>
  util::Status GetEntry(const std::string& path, EntryHandle<T>* entry) const;

  template <class T>
  util::Status GetAllEntriesInDir(const std::string& dir,
                                  std::vector<EntryHandle<T>>* entries) const;

  template <class T>
  util::Status UpdateEntry(EntryHandle<T>* entry);

  template <class T>
  util::Status CreateEntry(EntryHandle<T>* entry);

  template <class T>
  util::Status ForceSetEntry(EntryHandle<T>* entry);

  template <class T>
  util::Status ForceSetEntryWithTTL(const std::chrono::seconds& ttl,
                                    EntryHandle<T>* entry);

  template <class T>
  util::Status DeleteEntry(EntryHandle<T>* entry);

  std::string GetUnsequencedPath(const Logged& unseq) const;

  std::string GetUnsequencedPath(const std::string& hash) const;

  std::string GetSequencedPath(int64_t seq) const;

  std::string GetNodePath(const std::string& node_id) const;

  std::string GetFullPath(const std::string& key) const;


  // The following 3 methods are static just so that they have friend access to
  // the private c'tor/setters of Update<>

  // Converts a single WatchUpdate to an Update<T> (using
  // TypedUpdateFromWatchUpdate() below), and calls |callback| with it.
  template <class T, class CB>
  static void ConvertSingleUpdate(
      const std::string& full_path, const CB& callback,
      const std::vector<EtcdClient::WatchUpdate>& updates);

  // Converts a vector of WatchUpdates to a vector<Update<T>> (using
  // TypedUpdateFromWatchUpdate() below), and calls |callback| with it.
  template <class T, class CB>
  static void ConvertMultipleUpdate(
      const CB& callback, const std::vector<EtcdClient::WatchUpdate>& updates);

  // Converts a generic WatchUpdate to an Update<T>.
  // T must implement ParseFromString().
  template <class T>
  static Update<T> TypedUpdateFromWatchUpdate(
      const EtcdClient::WatchUpdate& update);

  void UpdateLocalServingSTH(const std::unique_lock<std::mutex>& lock,
                             const EntryHandle<ct::SignedTreeHead>& handle);

  void OnEtcdServingSTHUpdated(const Update<ct::SignedTreeHead>& update);

  EtcdClient* const client_;  // We don't own this.
  util::Executor* const executor_;        // We don't own this.
  const MasterElection* const election_;  // We don't own this.
  const std::string root_;
  const std::string node_id_;
  std::condition_variable serving_sth_cv_;
  util::SyncTask serving_sth_watch_task_;

  mutable std::mutex mutex_;
  bool received_initial_sth_;
  std::unique_ptr<EntryHandle<ct::SignedTreeHead>> serving_sth_;
  bool exiting_;

  friend class EtcdConsistentStoreTest;

  DISALLOW_COPY_AND_ASSIGN(EtcdConsistentStore);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_H_
