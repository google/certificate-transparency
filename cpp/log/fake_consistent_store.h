#ifndef CERT_TRANS_LOG_FAKE_CONSISTENT_STORE_H_
#define CERT_TRANS_LOG_FAKE_CONSISTENT_STORE_H_

#include <memory>
#include <stdint.h>
#include <mutex>
#include <vector>

#include "base/macros.h"
#include "log/consistent_store.h"
#include "proto/ct.pb.h"
#include "util/status.h"


namespace cert_trans {


template <class Logged>
class FakeConsistentStore : public ConsistentStore<Logged> {
 public:
  explicit FakeConsistentStore(const std::string& node_id);

  virtual ~FakeConsistentStore() = default;

  uint64_t NextAvailableSequenceNumber() const override;

  util::Status SetServingSTH(const ct::SignedTreeHead& new_sth) override;

  util::Status AddPendingEntry(Logged* entry) override;

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
  mutable std::mutex mutex_;
  std::map<std::string, EntryHandle<Logged>> pending_entries_;
  std::map<std::string, EntryHandle<Logged>> sequenced_entries_;
  std::map<std::string, ct::ClusterNodeState> node_states_;
  std::unique_ptr<ct::SignedTreeHead> tree_head_;

  const std::string node_id_;
  int next_available_sequence_number_;

  friend class FakeConsistentStoreTest;

  DISALLOW_COPY_AND_ASSIGN(FakeConsistentStore);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_FAKE_CONSISTENT_STORE_H_
