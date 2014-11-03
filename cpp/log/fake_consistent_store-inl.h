#ifndef CERT_TRANS_LOG_FAKE_CONSISTENT_STORE_INL_H_
#define CERT_TRANS_LOG_FAKE_CONSISTENT_STORE_INL_H_

#include <glog/logging.h>
#include <mutex>

#include "log/fake_consistent_store.h"
#include "log/logged_certificate.h"
#include "util/util.h"

namespace cert_trans {


template <class Logged>
FakeConsistentStore<Logged>::FakeConsistentStore(const std::string& node_id)
    : node_id_(node_id), next_available_sequence_number_(0) {
}


template <class Logged>
uint64_t FakeConsistentStore<Logged>::NextAvailableSequenceNumber() const {
  std::unique_lock<std::mutex> lock(mutex_);
  return next_available_sequence_number_;
}


template <class Logged>
util::Status FakeConsistentStore<Logged>::SetServingSTH(
    const ct::SignedTreeHead& new_sth) {
  std::unique_lock<std::mutex> lock(mutex_);
  tree_head_.reset(new ct::SignedTreeHead(new_sth));
  return util::Status::OK;
}


template <class Logged>
util::Status FakeConsistentStore<Logged>::AddPendingEntry(Logged* entry) {
  CHECK_NOTNULL(entry);
  CHECK(!entry->has_sequence_number());
  std::unique_lock<std::mutex> lock(mutex_);
  const std::string path(util::ToBase64(entry->Hash()));
  if (pending_entries_.find(path) != pending_entries_.end()) {
    *entry = pending_entries_[path].Entry();
    return util::Status(util::error::ALREADY_EXISTS, "");
  } else {
    pending_entries_.emplace(path, EntryHandle<Logged>(*entry, 0));
  }
  return util::Status::OK;
}


template <class Logged>
util::Status FakeConsistentStore<Logged>::GetPendingEntries(
    std::vector<EntryHandle<Logged>>* entries) const {
  std::unique_lock<std::mutex> lock(mutex_);
  for (const auto& entry : pending_entries_) {
    entries->emplace_back(
        EntryHandle<Logged>(entry.second.Entry(), entry.second.Handle()));
    CHECK(!entry.second.Entry().has_sequence_number());
  }
  return util::Status::OK;
}


template <class Logged>
util::Status FakeConsistentStore<Logged>::GetSequencedEntries(
    std::vector<EntryHandle<Logged>>* entries) const {
  std::unique_lock<std::mutex> lock(mutex_);
  for (const auto& entry : sequenced_entries_) {
    entries->emplace_back(
        EntryHandle<Logged>(entry.second.Entry(), entry.second.Handle()));
    CHECK(entry.second.Entry().has_sequence_number());
  }
  return util::Status::OK;
}


template <class Logged>
util::Status FakeConsistentStore<Logged>::GetSequencedEntry(
    const uint64_t sequence_number, EntryHandle<Logged>* entry) const {
  std::unique_lock<std::mutex> lock(mutex_);
  const std::string path(std::to_string(sequence_number));
  auto it(sequenced_entries_.find(path));
  if (it == sequenced_entries_.end()) {
    return util::Status(util::error::NOT_FOUND, "");
  }
  const EntryHandle<Logged>& sequenced(it->second);
  entry->Set(sequenced.Entry(), sequenced.Handle());
  CHECK(entry->Entry().has_sequence_number());
  return util::Status::OK;
}


template <class Logged>
util::Status FakeConsistentStore<Logged>::AssignSequenceNumber(
    const uint64_t sequence_number, EntryHandle<Logged>* entry) {
  CHECK(!entry->Entry().has_sequence_number());
  CHECK_EQ(sequence_number, next_available_sequence_number_);
  std::unique_lock<std::mutex> lock(mutex_);
  entry->MutableEntry()->set_provisional_sequence_number(sequence_number);
  const std::string pending_path(util::ToBase64(entry->Entry().Hash()));
  if (pending_entries_.find(pending_path) != pending_entries_.end()) {
    // already exists
    if (pending_entries_[pending_path].Handle() != entry->Handle()) {
      return util::Status(util::error::FAILED_PRECONDITION,
                          "Bad handle version");
    }
  }
  entry->SetHandle(entry->Handle() + 1);
  pending_entries_[pending_path].Set(entry->Entry(), entry->Handle());

  const std::string seq_path(std::to_string(sequence_number));
  if (sequenced_entries_.find(seq_path) != sequenced_entries_.end()) {
    return util::Status(util::error::ALREADY_EXISTS,
                        "Sequenced entry already exists");
  }
  entry->MutableEntry()->set_sequence_number(sequence_number);
  sequenced_entries_.emplace(seq_path, EntryHandle<Logged>(entry->Entry(), 0));
  next_available_sequence_number_++;
  return util::Status::OK;
}


template <class Logged>
util::Status FakeConsistentStore<Logged>::SetClusterNodeState(
    const ct::ClusterNodeState& state) {
  // TODO(alcutter): need a ForceUpdate (i.e. not compare-and-update)
  return util::Status(util::error::UNIMPLEMENTED, "Not implemented yet.");
}


}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_INL_H_
