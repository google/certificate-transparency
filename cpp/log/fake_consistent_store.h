#ifndef CERT_TRANS_LOG_FAKE_CONSISTENT_STORE_H_
#define CERT_TRANS_LOG_FAKE_CONSISTENT_STORE_H_

#include <memory>
#include <mutex>
#include <vector>

#include "base/macros.h"
#include "log/consistent_store.h"
#include "proto/ct.pb.h"
#include "util/status.h"

template <class Logged>
class ReadOnlyDatabase;

namespace cert_trans {


template <class Logged>
class FakeConsistentStore : public ConsistentStore<Logged> {
 public:
  // If a "db" is passed in, it will use the tree size of that
  // database to pick its next sequence number, which makes it work
  // across restarts. This still loses unsequenced entries, though,
  // since the database only receives sequenced entries.
  FakeConsistentStore(const std::string& node_id,
                      const ReadOnlyDatabase<Logged>* db = nullptr);

  virtual ~FakeConsistentStore() = default;

  int64_t NextAvailableSequenceNumber() const override;

  util::Status SetServingSTH(const ct::SignedTreeHead& new_sth) override;

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

  util::Status SetClusterNodeState(const ct::ClusterNodeState& state) override;

 private:
  mutable std::mutex mutex_;
  std::map<std::string, EntryHandle<Logged>> pending_entries_;
  std::map<std::string, EntryHandle<Logged>> sequenced_entries_;
  std::map<std::string, ct::ClusterNodeState> node_states_;
  std::unique_ptr<ct::SignedTreeHead> tree_head_;

  const std::string node_id_;
  int64_t next_available_sequence_number_;

  friend class FakeConsistentStoreTest;
  template <class T>
  friend class TreeSignerTest;

  DISALLOW_COPY_AND_ASSIGN(FakeConsistentStore);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_FAKE_CONSISTENT_STORE_H_
