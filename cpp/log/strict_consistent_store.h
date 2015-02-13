#ifndef CERT_TRANS_LOG_STRICT_CONSISTENT_STORE_H_
#define CERT_TRANS_LOG_STRICT_CONSISTENT_STORE_H_

#include "log/consistent_store.h"
#include "util/masterelection.h"

namespace cert_trans {

// A wrapper around a ConsistentStore which will not allow changes to
// the cluster state which should only be performed by the current master
// unless this node /is/ the current master.
//
// Note that while this is better than just gating the start of a high-level
// action (especially a long running action, e.g. a signing run) with a check
// to IsMaster(), it is still necessarily racy because etcd doesn't support
// atomic updates across keys.)
template <class Logged>
class StrictConsistentStore : public ConsistentStore<Logged> {
 public:
  // Takes ownership of |peer|, but not |election|
  StrictConsistentStore(const MasterElection* election,
                        ConsistentStore<Logged>* peer);

  virtual ~StrictConsistentStore() = default;

  // Methods requiring that the caller is currently master:

  util::StatusOr<int64_t> NextAvailableSequenceNumber() const override;

  util::Status SetServingSTH(const ct::SignedTreeHead& new_sth) override;

  util::Status AssignSequenceNumber(const int64_t sequence_number,
                                    EntryHandle<Logged>* entry) override;

  util::Status SetClusterConfig(const ct::ClusterConfig& config) override;

  // Other methods:

  util::StatusOr<ct::SignedTreeHead> GetServingSTH() const override {
    return peer_->GetServingSTH();
  }

  util::Status AddPendingEntry(Logged* entry) {
    return peer_->AddPendingEntry(entry);
  }

  util::Status GetPendingEntryForHash(const std::string& hash,
                                      EntryHandle<Logged>* entry) const {
    return peer_->GetPendingEntryForHash(hash, entry);
  }

  util::Status GetPendingEntries(
      std::vector<EntryHandle<Logged>>* entries) const {
    return peer_->GetPendingEntries(entries);
  }

  util::Status GetSequencedEntries(
      std::vector<EntryHandle<Logged>>* entries) const {
    return peer_->GetSequencedEntries(entries);
  }

  util::Status GetSequencedEntry(const int64_t sequence_number,
                                 EntryHandle<Logged>* entry) const {
    return peer_->GetSequencedEntry(sequence_number, entry);
  }

  util::Status GetClusterNodeState(ct::ClusterNodeState* state) const {
    return peer_->GetClusterNodeState(state);
  }

  util::Status SetClusterNodeState(const ct::ClusterNodeState& state) {
    return peer_->SetClusterNodeState(state);
  }

  void WatchServingSTH(
      const typename ConsistentStore<Logged>::ServingSTHCallback& cb,
      util::Task* task) {
    return peer_->WatchServingSTH(cb, task);
  }

  void WatchClusterNodeStates(
      const typename ConsistentStore<Logged>::ClusterNodeStateCallback& cb,
      util::Task* task) {
    return peer_->WatchClusterNodeStates(cb, task);
  }

  void WatchClusterConfig(
      const typename ConsistentStore<Logged>::ClusterConfigCallback& cb,
      util::Task* task) {
    return peer_->WatchClusterConfig(cb, task);
  }

 private:
  const MasterElection* const election_;  // Not owned by us
  const std::unique_ptr<ConsistentStore<Logged>> peer_;
};


}  // namespace

#endif  // CERT_TRANS_LOG_STRICT_CONSISTENT_STORE_H_
