#ifndef CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_INL_H_
#define CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_INL_H_

#include <glog/logging.h>

#include "base/notification.h"
#include "log/consistent_store-inl.h"
#include "log/etcd_consistent_store.h"
#include "log/logged_certificate.h"
#include "util/executor.h"
#include "util/util.h"

DECLARE_int32(node_state_ttl_seconds);

namespace cert_trans {
namespace {

// etcd path constants.
const char kUnsequencedDir[] = "/unsequenced/";
const char kSequencedDir[] = "/sequenced/";
const char kServingSthFile[] = "/serving_sth";
const char kNodesDir[] = "/nodes/";

}  // namespace


template <class Logged>
EtcdConsistentStore<Logged>::EtcdConsistentStore(util::Executor* executor,
                                                 EtcdClient* client,
                                                 const std::string& root,
                                                 const std::string& node_id)
    : client_(CHECK_NOTNULL(client)),
      sync_client_(client),
      root_(root),
      node_id_(node_id),
      serving_sth_watch_task_(CHECK_NOTNULL(executor)),
      cluster_node_states_watch_task_(CHECK_NOTNULL(executor)),
      received_initial_sth_(false) {
  // Set up watches on things we're interested in...
  client_->Watch(
      GetFullPath(kServingSthFile),
      std::bind(&EtcdConsistentStore<Logged>::OnEtcdServingSTHUpdated, this,
                std::placeholders::_1),
      serving_sth_watch_task_.task());

  client_->Watch(
      GetFullPath(kNodesDir),
      std::bind(&EtcdConsistentStore<Logged>::OnEtcdClusterNodeStatesUpdated,
                this, std::placeholders::_1),
      cluster_node_states_watch_task_.task());

  // And wait for the initial updates to come back so that we've got a
  // view on the current state before proceding...
  {
    std::unique_lock<std::mutex> lock(mutex_);
    serving_sth_cv_.wait(lock, [this]() { return received_initial_sth_; });
  }
  initial_cluster_notify_.WaitForNotification();
}


template <class Logged>
EtcdConsistentStore<Logged>::~EtcdConsistentStore() {
  VLOG(1) << "Cancelling watch tasks.";
  serving_sth_watch_task_.Cancel();
  cluster_node_states_watch_task_.Cancel();
  VLOG(1) << "Waiting for watch tasks to return.";
  serving_sth_watch_task_.Wait();
  cluster_node_states_watch_task_.Wait();
}


template <class Logged>
util::StatusOr<int64_t>
EtcdConsistentStore<Logged>::NextAvailableSequenceNumber() const {
  std::vector<EntryHandle<Logged>> sequenced_entries;
  util::Status status(GetSequencedEntries(&sequenced_entries));
  if (!status.ok()) {
    return status;
  }
  if (!sequenced_entries.empty()) {
    CHECK(sequenced_entries.back().Entry().has_sequence_number());
    return sequenced_entries.back().Entry().sequence_number() + 1;
  }

  // TODO(alcutter): Implement the rest of the logic around /serving_sth too
  // once there are methods to inspect that.
  LOG(WARNING) << "NextAvailableSequenceNumber() not checking /serving_sth.";
  return 0;
}


template <class Logged>
void EtcdConsistentStore<Logged>::WaitForServingSTHVersion(
    std::unique_lock<std::mutex>* lock, const int version) {
  VLOG(1) << "Waiting for ServingSTH version " << version;
  serving_sth_cv_.wait(*lock, [this, version]() {
    return serving_sth_.get() != nullptr && serving_sth_->Handle() >= version;
  });
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::SetServingSTH(
    const ct::SignedTreeHead& new_sth) {
  const std::string full_path(GetFullPath(kServingSthFile));
  std::unique_lock<std::mutex> lock(mutex_);

  // The watcher should have already populated serving_sth_ if etcd had one.
  if (!serving_sth_) {
    // Looks like we're creating the first ever serving_sth!
    LOG(WARNING) << "Creating new " << full_path;
    // There's no current serving STH, so we can try to create one.
    EntryHandle<ct::SignedTreeHead> sth_handle(new_sth);
    util::Status status(CreateEntry(full_path, &sth_handle));
    if (!status.ok()) {
      return status;
    }
    WaitForServingSTHVersion(&lock, sth_handle.Handle());
    return util::Status::OK;
  }

  // Looks like we're updating an existing serving_sth.
  // First check that we're not trying to overwrite it with itself or an older
  // one:
  if (serving_sth_->Entry().timestamp() >= new_sth.timestamp()) {
    return util::Status(util::error::OUT_OF_RANGE,
                        "Tree head is not newer than existing head");
  }

  // Ensure that nothing weird is going on with the tree size:
  CHECK_LE(serving_sth_->Entry().tree_size(), new_sth.tree_size());

  VLOG(1) << "Updating existing " << full_path;
  EntryHandle<ct::SignedTreeHead> sth_to_etcd(new_sth, serving_sth_->Handle());
  util::Status status(UpdateEntry(full_path, &sth_to_etcd));
  if (!status.ok()) {
    return status;
  }
  WaitForServingSTHVersion(&lock, sth_to_etcd.Handle());
  return util::Status::OK;
}


template <class Logged>
bool LeafEntriesMatch(const Logged& a, const Logged& b) {
  CHECK_EQ(a.entry().type(), b.entry().type());
  switch (a.entry().type()) {
    case ct::X509_ENTRY:
      return a.entry().x509_entry().leaf_certificate() ==
             b.entry().x509_entry().leaf_certificate();
    case ct::PRECERT_ENTRY:
      return a.entry().precert_entry().pre_certificate() ==
             b.entry().precert_entry().pre_certificate();
    case ct::UNKNOWN_ENTRY_TYPE:
      LOG(FATAL) << "Encountered UNKNOWN_ENTRY_TYPE:\n"
                 << a.entry().DebugString();
  }
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::AddPendingEntry(Logged* entry) {
  CHECK_NOTNULL(entry);
  CHECK(!entry->has_sequence_number());
  const std::string full_path(GetUnsequencedPath(*entry));
  EntryHandle<Logged> handle(*entry);
  util::Status status(CreateEntry(full_path, &handle));
  if (status.CanonicalCode() == util::error::FAILED_PRECONDITION) {
    // Entry with that hash already exists.
    EntryHandle<Logged> preexisting_entry;
    status = GetEntry(full_path, &preexisting_entry);
    if (!status.ok()) {
      LOG(ERROR) << "Couldn't create or fetch " << full_path << " : "
                 << status;
      return status;
    }

    // Check the leaf certs are the same (we might be seeing the same cert
    // submitted with a different chain.)
    CHECK(LeafEntriesMatch(preexisting_entry.Entry(), *entry));
    *entry->mutable_sct() = preexisting_entry.Entry().sct();
    return util::Status(util::error::ALREADY_EXISTS,
                        "Pending entry already exists.");
  }
  return status;
}

template <class Logged>
util::Status EtcdConsistentStore<Logged>::GetPendingEntryForHash(
    const std::string& hash, EntryHandle<Logged>* entry) const {
  util::Status status(GetEntry(GetUnsequencedPath(hash), entry));
  if (status.ok()) {
    CHECK(!entry->Entry().has_sequence_number());
  }

  return status;
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::GetPendingEntries(
    std::vector<EntryHandle<Logged>>* entries) const {
  util::Status status(
      GetAllEntriesInDir(GetFullPath(kUnsequencedDir), entries));
  if (status.ok()) {
    for (const auto& entry : *entries) {
      CHECK(!entry.Entry().has_sequence_number());
    }
  }
  return status;
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::GetSequencedEntries(
    std::vector<EntryHandle<Logged>>* entries) const {
  util::Status status(GetAllEntriesInDir(GetFullPath(kSequencedDir), entries));
  if (status.ok()) {
    for (const auto& entry : *entries) {
      CHECK(entry.Entry().has_sequence_number());
    }
  }
  return status;
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::GetSequencedEntry(
    const int64_t sequence_number, EntryHandle<Logged>* entry) const {
  CHECK_GE(sequence_number, 0);
  util::Status status(GetEntry(GetSequencedPath(sequence_number), entry));
  if (status.ok()) {
    CHECK(entry->Entry().has_sequence_number());
  }

  return status;
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::AssignSequenceNumber(
    const int64_t sequence_number, EntryHandle<Logged>* entry) {
  CHECK_GE(sequence_number, 0);
  CHECK(!entry->Entry().has_sequence_number());
  if (entry->Entry().has_provisional_sequence_number()) {
    CHECK_EQ(sequence_number, entry->Entry().provisional_sequence_number());
  } else {
    entry->MutableEntry()->set_provisional_sequence_number(sequence_number);
  }
  // Record provisional sequence number:
  util::Status status(UpdateEntry(GetUnsequencedPath(entry->Entry()), entry));
  if (!status.ok()) {
    return status;
  }
  // Now finalise the sequence number assignment.
  // Create a temporary EntryHandle here to avoid stomping over the version
  // info held by the unsequenced entry handle passed in:
  EntryHandle<Logged> seq_entry(entry->Entry());
  seq_entry.MutableEntry()->clear_provisional_sequence_number();
  seq_entry.MutableEntry()->set_sequence_number(sequence_number);
  return CreateEntry(GetSequencedPath(sequence_number), &seq_entry);
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::SetClusterNodeState(
    const ct::ClusterNodeState& state) {
  // TODO(alcutter): consider keeping the handle for this around to check that
  // nobody else is updating our cluster state.
  ct::ClusterNodeState local_state(state);
  local_state.set_node_id(node_id_);
  EntryHandle<ct::ClusterNodeState> entry(local_state);
  const std::chrono::seconds ttl(FLAGS_node_state_ttl_seconds);
  return ForceSetEntryWithTTL(GetNodePath(node_id_), ttl, &entry);
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::GetEntry(
    const std::string& path, EntryHandle<T>* entry) const {
  CHECK_NOTNULL(entry);
  EtcdClient::Node node;
  util::Status status(sync_client_.Get(path, &node));
  if (!status.ok()) {
    return status;
  }
  T t;
  CHECK(t.ParseFromString(util::FromBase64(node.value_.c_str())));
  entry->Set(t, node.modified_index_);
  return util::Status::OK;
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::GetAllEntriesInDir(
    const std::string& dir, std::vector<EntryHandle<T>>* entries) const {
  CHECK_NOTNULL(entries);
  CHECK_EQ(0, entries->size());
  std::vector<EtcdClient::Node> nodes;
  util::Status status(sync_client_.GetAll(dir, &nodes));
  if (!status.ok()) {
    return status;
  }
  for (const auto& node : nodes) {
    T t;
    CHECK(t.ParseFromString(util::FromBase64(node.value_.c_str())));
    entries->emplace_back(EntryHandle<Logged>(t, node.modified_index_));
  }
  return util::Status::OK;
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::UpdateEntry(const std::string& path,
                                                      EntryHandle<T>* t) {
  CHECK_NOTNULL(t);
  CHECK(t->HasHandle());
  std::string flat_entry;
  CHECK(t->Entry().SerializeToString(&flat_entry));
  int64_t new_version;
  util::Status status(sync_client_.Update(path, util::ToBase64(flat_entry),
                                          t->Handle(), &new_version));
  if (status.ok()) {
    t->SetHandle(new_version);
  }
  return status;
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::CreateEntry(const std::string& path,
                                                      EntryHandle<T>* t) {
  CHECK_NOTNULL(t);
  CHECK(!t->HasHandle());
  std::string flat_entry;
  CHECK(t->Entry().SerializeToString(&flat_entry));
  int64_t new_version;
  util::Status status(
      sync_client_.Create(path, util::ToBase64(flat_entry), &new_version));
  if (status.ok()) {
    t->SetHandle(new_version);
  }
  return status;
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::ForceSetEntry(
    const std::string& path, EntryHandle<T>* t) {
  CHECK_NOTNULL(t);
  CHECK(!t->HasHandle());
  std::string flat_entry;
  CHECK(t->Entry().SerializeToString(&flat_entry));
  int64_t new_version;
  util::Status status(
      sync_client_.ForceSet(path, util::ToBase64(flat_entry), &new_version));
  if (status.ok()) {
    t->SetHandle(new_version);
  }
  return status;
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::ForceSetEntryWithTTL(
    const std::string& path, const std::chrono::seconds& ttl,
    EntryHandle<T>* t) {
  CHECK_NOTNULL(t);
  CHECK(!t->HasHandle());
  CHECK_LE(0, ttl.count());
  std::string flat_entry;
  CHECK(t->Entry().SerializeToString(&flat_entry));
  int64_t new_version;
  util::Status status(sync_client_.ForceSetWithTTL(path,
                                                   util::ToBase64(flat_entry),
                                                   ttl, &new_version));
  if (status.ok()) {
    t->SetHandle(new_version);
  }
  return status;
}


template <class Logged>
std::string EtcdConsistentStore<Logged>::GetUnsequencedPath(
    const Logged& unseq) const {
  return GetFullPath(std::string(kUnsequencedDir) +
                     util::ToBase64(unseq.Hash()));
}


template <class Logged>
std::string EtcdConsistentStore<Logged>::GetUnsequencedPath(
    const std::string& hash) const {
  return GetFullPath(std::string(kUnsequencedDir) + util::ToBase64(hash));
}


template <class Logged>
std::string EtcdConsistentStore<Logged>::GetNodePath(
    const std::string& id) const {
  return GetFullPath(std::string(kNodesDir) + id);
}


template <class Logged>
std::string EtcdConsistentStore<Logged>::GetSequencedPath(int64_t seq) const {
  CHECK_GE(seq, 0);
  return GetFullPath(std::string(kSequencedDir) + std::to_string(seq));
}


template <class Logged>
std::string EtcdConsistentStore<Logged>::GetFullPath(
    const std::string& key) const {
  CHECK(key.size() > 0);
  CHECK_EQ('/', key[0]);
  return root_ + key;
}


// static
template <class Logged>
template <class T>
Update<T> EtcdConsistentStore<Logged>::TypedUpdateFromWatchUpdate(
    const EtcdClient::WatchUpdate& update) {
  const std::string raw_value(util::FromBase64(update.node_.value_.c_str()));
  T thing;
  CHECK(thing.ParseFromString(raw_value)) << raw_value;
  EntryHandle<T> handle(thing);
  if (update.exists_) {
    handle.SetHandle(update.node_.modified_index_);
  }
  return Update<T>(handle, update.exists_);
}


template <class Logged>
void EtcdConsistentStore<Logged>::UpdateLocalServingSTH(
    const std::unique_lock<std::mutex>& lock,
    const EntryHandle<ct::SignedTreeHead>& handle) {
  CHECK(lock.owns_lock());
  CHECK(!serving_sth_ ||
        serving_sth_->Entry().timestamp() < handle.Entry().timestamp());

  VLOG(1) << "Updating serving_sth_ to: " << handle.Entry().DebugString();
  serving_sth_.reset(new EntryHandle<ct::SignedTreeHead>(handle));
}


template <class Logged>
void EtcdConsistentStore<Logged>::OnEtcdServingSTHUpdated(
    const std::vector<EtcdClient::WatchUpdate>& updates) {
  CHECK_LE(updates.size(), 1);
  std::unique_lock<std::mutex> lock(mutex_);
  if (!updates.empty()) {
    const Update<ct::SignedTreeHead> update(
        TypedUpdateFromWatchUpdate<ct::SignedTreeHead>(updates[0]));
    VLOG(1) << "Got ServingSTH version " << update.handle_.Handle();
    UpdateLocalServingSTH(lock, update.handle_);
    this->OnServingSTHUpdate(update);
  }
  received_initial_sth_ = true;
  lock.unlock();
  serving_sth_cv_.notify_all();
}


template <class Logged>
void EtcdConsistentStore<Logged>::OnEtcdClusterNodeStatesUpdated(
    const std::vector<EtcdClient::WatchUpdate>& watch_updates) {
  std::vector<Update<ct::ClusterNodeState>> updates;
  for (const auto& u : watch_updates) {
    updates.emplace_back(TypedUpdateFromWatchUpdate<ct::ClusterNodeState>(u));
  }
  this->OnClusterNodeStatesUpdate(updates);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initial_cluster_notify_.HasBeenNotified()) {
      initial_cluster_notify_.Notify();
    }
  }
}


}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_INL_H_
