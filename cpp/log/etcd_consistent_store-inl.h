#ifndef CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_INL_H_
#define CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_INL_H_

#include <glog/logging.h>

#include "base/notification.h"
#include "log/etcd_consistent_store.h"
#include "log/logged_certificate.h"
#include "util/executor.h"
#include "util/masterelection.h"
#include "util/util.h"

DECLARE_int32(node_state_ttl_seconds);

namespace cert_trans {
namespace {

// etcd path constants.
const char kClusterConfigFile[] = "/cluster_config";
const char kUnsequencedDir[] = "/unsequenced/";
const char kSequencedDir[] = "/sequenced/";
const char kServingSthFile[] = "/serving_sth";
const char kNodesDir[] = "/nodes/";

}  // namespace


template <class Logged>
EtcdConsistentStore<Logged>::EtcdConsistentStore(
    util::Executor* executor, EtcdClient* client,
    const MasterElection* election, const std::string& root,
    const std::string& node_id)
    : client_(CHECK_NOTNULL(client)),
      executor_(CHECK_NOTNULL(executor)),
      election_(CHECK_NOTNULL(election)),
      root_(root),
      node_id_(node_id),
      serving_sth_watch_task_(CHECK_NOTNULL(executor)),
      received_initial_sth_(false),
      exiting_(false) {
  // Set up watches on things we're interested in...
  WatchServingSTH(
      std::bind(&EtcdConsistentStore<Logged>::OnEtcdServingSTHUpdated, this,
                std::placeholders::_1),
      serving_sth_watch_task_.task());

  // And wait for the initial updates to come back so that we've got a
  // view on the current state before proceding...
  {
    std::unique_lock<std::mutex> lock(mutex_);
    serving_sth_cv_.wait(lock, [this]() { return received_initial_sth_; });
  }
}


template <class Logged>
EtcdConsistentStore<Logged>::~EtcdConsistentStore() {
  VLOG(1) << "Cancelling watch tasks.";
  serving_sth_watch_task_.Cancel();
  VLOG(1) << "Waiting for watch tasks to return.";
  serving_sth_watch_task_.Wait();
  VLOG(1) << "Joining cleanup thread";
  {
    std::lock_guard<std::mutex> lock(mutex_);
    exiting_ = true;
  }
  serving_sth_cv_.notify_all();
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

  if (!serving_sth_) {
    LOG(WARNING) << "Log has no Serving STH [new log?], returning 0";
    return 0;
  }

  return serving_sth_->Entry().tree_size();
}


template <class Logged>
void EtcdConsistentStore<Logged>::WaitForServingSTHVersion(
    std::unique_lock<std::mutex>* lock, const int version) {
  VLOG(1) << "Waiting for ServingSTH version " << version;
  serving_sth_cv_.wait(*lock, [this, version]() {
    VLOG(1) << "Want version " << version << ", have: "
            << (serving_sth_ ? std::to_string(serving_sth_->Handle())
                             : "none");
    return serving_sth_ && serving_sth_->Handle() >= version;
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
    EntryHandle<ct::SignedTreeHead> sth_handle(full_path, new_sth);
    util::Status status(CreateEntry(&sth_handle));
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
  EntryHandle<ct::SignedTreeHead> sth_to_etcd(full_path, new_sth,
                                              serving_sth_->Handle());
  util::Status status(UpdateEntry(&sth_to_etcd));
  if (!status.ok()) {
    return status;
  }
  WaitForServingSTHVersion(&lock, sth_to_etcd.Handle());
  return util::Status::OK;
}


template <class Logged>
util::StatusOr<ct::SignedTreeHead> EtcdConsistentStore<Logged>::GetServingSTH()
    const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (serving_sth_) {
    return serving_sth_->Entry();
  } else {
    return util::Status(util::error::NOT_FOUND, "No current Serving STH.");
  }
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
  EntryHandle<Logged> handle(full_path, *entry);
  util::Status status(CreateEntry(&handle));
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
bool LessBySequenceNumber(const EntryHandle<Logged>& lhs,
                          const EntryHandle<Logged>& rhs) {
  CHECK(lhs.Entry().has_sequence_number());
  CHECK(rhs.Entry().has_sequence_number());
  return lhs.Entry().sequence_number() < rhs.Entry().sequence_number();
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::GetSequencedEntries(
    std::vector<EntryHandle<Logged>>* entries) const {
  util::Status status(GetAllEntriesInDir(GetFullPath(kSequencedDir), entries));
  sort(entries->begin(), entries->end(), LessBySequenceNumber<Logged>);
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
  util::Status status(UpdateEntry(entry));
  if (!status.ok()) {
    return status;
  }
  // Now finalise the sequence number assignment.
  // Create a temporary EntryHandle here to avoid stomping over the version
  // info held by the unsequenced entry handle passed in:
  EntryHandle<Logged> seq_entry(GetSequencedPath(sequence_number),
                                entry->Entry());
  seq_entry.MutableEntry()->clear_provisional_sequence_number();
  seq_entry.MutableEntry()->set_sequence_number(sequence_number);
  return CreateEntry(&seq_entry);
}


template <class Logged>
util::StatusOr<ct::ClusterNodeState>
EtcdConsistentStore<Logged>::GetClusterNodeState() const {
  EntryHandle<ct::ClusterNodeState> handle;
  util::Status status(GetEntry(GetNodePath(node_id_), &handle));
  if (!status.ok()) {
    return status;
  }
  return handle.Entry();
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::SetClusterNodeState(
    const ct::ClusterNodeState& state) {
  // TODO(alcutter): consider keeping the handle for this around to check that
  // nobody else is updating our cluster state.
  ct::ClusterNodeState local_state(state);
  local_state.set_node_id(node_id_);
  EntryHandle<ct::ClusterNodeState> entry(GetNodePath(node_id_), local_state);
  const std::chrono::seconds ttl(FLAGS_node_state_ttl_seconds);
  return ForceSetEntryWithTTL(ttl, &entry);
}


// static
template <class Logged>
template <class T, class CB>
void EtcdConsistentStore<Logged>::ConvertSingleUpdate(
    const std::string& full_path, const CB& callback,
    const std::vector<EtcdClient::Node>& updates) {
  CHECK_LE(0, updates.size());
  if (updates.empty()) {
    EntryHandle<T> handle;
    handle.SetKey(full_path);
    callback(Update<T>(handle, false /* exists */));
  } else {
    callback(TypedUpdateFromNode<T>(updates[0]));
  }
}


// static
template <class Logged>
template <class T, class CB>
void EtcdConsistentStore<Logged>::ConvertMultipleUpdate(
    const CB& callback, const std::vector<EtcdClient::Node>& watch_updates) {
  std::vector<Update<T>> updates;
  for (auto& w : watch_updates) {
    updates.emplace_back(TypedUpdateFromNode<T>(w));
  }
  callback(updates);
}


template <class Logged>
void EtcdConsistentStore<Logged>::WatchServingSTH(
    const typename ConsistentStore<Logged>::ServingSTHCallback& cb,
    util::Task* task) {
  const std::string full_path(GetFullPath(kServingSthFile));
  client_->Watch(
      full_path,
      std::bind(&ConvertSingleUpdate<
                    ct::SignedTreeHead,
                    typename ConsistentStore<Logged>::ServingSTHCallback>,
                full_path, cb, std::placeholders::_1),
      task);
}


template <class Logged>
void EtcdConsistentStore<Logged>::WatchClusterNodeStates(
    const typename ConsistentStore<Logged>::ClusterNodeStateCallback& cb,
    util::Task* task) {
  client_->Watch(
      GetFullPath(kNodesDir),
      std::bind(
          &ConvertMultipleUpdate<
              ct::ClusterNodeState,
              typename ConsistentStore<Logged>::ClusterNodeStateCallback>,
          cb, std::placeholders::_1),
      task);
}


template <class Logged>
void EtcdConsistentStore<Logged>::WatchClusterConfig(
    const typename ConsistentStore<Logged>::ClusterConfigCallback& cb,
    util::Task* task) {
  const std::string full_path(GetFullPath(kClusterConfigFile));
  client_->Watch(
      full_path,
      std::bind(&ConvertSingleUpdate<
                    ct::ClusterConfig,
                    typename ConsistentStore<Logged>::ClusterConfigCallback>,
                full_path, cb, std::placeholders::_1),
      task);
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::SetClusterConfig(
    const ct::ClusterConfig& config) {
  EntryHandle<ct::ClusterConfig> entry(GetFullPath(kClusterConfigFile),
                                       config);
  return ForceSetEntry(&entry);
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::GetEntry(
    const std::string& path, EntryHandle<T>* entry) const {
  CHECK_NOTNULL(entry);
  util::SyncTask task(executor_);
  EtcdClient::GetResponse resp;
  client_->Get(path, &resp, task.task());
  task.Wait();
  if (!task.status().ok()) {
    return task.status();
  }
  T t;
  CHECK(t.ParseFromString(util::FromBase64(resp.node.value_.c_str())));
  entry->Set(path, t, resp.node.modified_index_);
  return util::Status::OK;
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::GetAllEntriesInDir(
    const std::string& dir, std::vector<EntryHandle<T>>* entries) const {
  CHECK_NOTNULL(entries);
  CHECK_EQ(0, entries->size());
  util::SyncTask task(executor_);
  EtcdClient::GetAllResponse resp;
  client_->GetAll(dir, &resp, task.task());
  task.Wait();
  if (!task.status().ok()) {
    return task.status();
  }
  for (const auto& node : resp.nodes) {
    T t;
    CHECK(t.ParseFromString(util::FromBase64(node.value_.c_str())));
    entries->emplace_back(
        EntryHandle<Logged>(node.key_, t, node.modified_index_));
  }
  return util::Status::OK;
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::UpdateEntry(EntryHandle<T>* t) {
  CHECK_NOTNULL(t);
  CHECK(t->HasHandle());
  CHECK(t->HasKey());
  std::string flat_entry;
  CHECK(t->Entry().SerializeToString(&flat_entry));
  util::SyncTask task(executor_);
  EtcdClient::Response resp;
  client_->Update(t->Key(), util::ToBase64(flat_entry), t->Handle(), &resp,
                  task.task());
  task.Wait();
  if (task.status().ok()) {
    t->SetHandle(resp.etcd_index);
  }
  return task.status();
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::CreateEntry(EntryHandle<T>* t) {
  CHECK_NOTNULL(t);
  CHECK(!t->HasHandle());
  CHECK(t->HasKey());
  std::string flat_entry;
  CHECK(t->Entry().SerializeToString(&flat_entry));
  util::SyncTask task(executor_);
  EtcdClient::Response resp;
  client_->Create(t->Key(), util::ToBase64(flat_entry), &resp, task.task());
  task.Wait();
  if (task.status().ok()) {
    t->SetHandle(resp.etcd_index);
  }
  return task.status();
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::ForceSetEntry(EntryHandle<T>* t) {
  CHECK_NOTNULL(t);
  CHECK(t->HasKey());
  // For now we check that |t| wasn't fetched from the etcd store (i.e. it's a
  // new EntryHandle.  The reason is that if it had been fetched, then the
  // calling code should be doing an UpdateEntry() here since they have the
  // handle.
  CHECK(!t->HasHandle());
  std::string flat_entry;
  CHECK(t->Entry().SerializeToString(&flat_entry));
  util::SyncTask task(executor_);
  EtcdClient::Response resp;
  client_->ForceSet(t->Key(), util::ToBase64(flat_entry), &resp, task.task());
  task.Wait();
  if (task.status().ok()) {
    t->SetHandle(resp.etcd_index);
  }
  return task.status();
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::ForceSetEntryWithTTL(
    const std::chrono::seconds& ttl, EntryHandle<T>* t) {
  CHECK_NOTNULL(t);
  CHECK(t->HasKey());
  // For now we check that |t| wasn't fetched from the etcd store (i.e. it's a
  // new EntryHandle.  The reason is that if it had been fetched, then the
  // calling code should be doing an UpdateEntryWithTTL() here since they have
  // the handle.
  CHECK(!t->HasHandle());
  CHECK_LE(0, ttl.count());
  std::string flat_entry;
  CHECK(t->Entry().SerializeToString(&flat_entry));
  util::SyncTask task(executor_);
  EtcdClient::Response resp;
  client_->ForceSetWithTTL(t->Key(), util::ToBase64(flat_entry), ttl, &resp,
                           task.task());
  task.Wait();
  if (task.status().ok()) {
    t->SetHandle(resp.etcd_index);
  }
  return task.status();
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::DeleteEntry(EntryHandle<T>* entry) {
  CHECK_NOTNULL(entry);
  CHECK(entry->HasHandle());
  CHECK(entry->HasKey());
  util::SyncTask task(executor_);
  client_->Delete(entry->Key(), entry->Handle(), task.task());
  task.Wait();
  return task.status();
}


template <class Logged>
std::string EtcdConsistentStore<Logged>::GetUnsequencedPath(
    const Logged& unseq) const {
  return GetUnsequencedPath(unseq.Hash());
}


template <class Logged>
std::string EtcdConsistentStore<Logged>::GetUnsequencedPath(
    const std::string& hash) const {
  return GetFullPath(std::string(kUnsequencedDir) + util::HexString(hash));
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
Update<T> EtcdConsistentStore<Logged>::TypedUpdateFromNode(
    const EtcdClient::Node& node) {
  const std::string raw_value(util::FromBase64(node.value_.c_str()));
  T thing;
  CHECK(thing.ParseFromString(raw_value)) << raw_value;
  EntryHandle<T> handle(node.key_, thing);
  if (!node.deleted_) {
    handle.SetHandle(node.modified_index_);
  }
  return Update<T>(handle, !node.deleted_);
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
    const Update<ct::SignedTreeHead>& update) {
  VLOG(1) << "Got ServingSTH version " << update.handle_.Handle() << ": "
          << update.handle_.Entry().DebugString();
  std::unique_lock<std::mutex> lock(mutex_);

  if (update.exists_) {
    UpdateLocalServingSTH(lock, update.handle_);
  } else {
    LOG(WARNING) << "ServingSTH non-existent/deleted.";
    // TODO(alcutter): What to do here?
    serving_sth_.reset();
  }
  received_initial_sth_ = true;
  lock.unlock();
  serving_sth_cv_.notify_all();
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::CleanupOldEntries() {
  if (!election_->IsMaster()) {
    return util::Status(util::error::PERMISSION_DENIED,
                        "Non-master node cannot run cleanups.");
  }

  // Figure out where we're cleaning up to...
  std::unique_lock<std::mutex> lock(mutex_);
  if (!serving_sth_) {
    LOG(INFO) << "No current serving_sth, nothing to do.";
    return util::Status::OK;
  }
  const int64_t clean_up_to_sequence_number(
      serving_sth_->Entry().tree_size() - 1);
  lock.unlock();

  LOG(INFO) << "Cleaning old entries up to and including sequence number: "
            << clean_up_to_sequence_number;

  std::vector<EntryHandle<Logged>> sequenced_entries;
  util::Status status(GetSequencedEntries(&sequenced_entries));
  if (!status.ok()) {
    LOG(WARNING) << "Couldn't get sequenced entries: " << status;
    return status;
  }

  for (auto& entry : sequenced_entries) {
    const uint64_t sequence_number(entry.Entry().sequence_number());

    // return if we've hit the limit
    if (entry.Entry().sequence_number() > clean_up_to_sequence_number) {
      return util::Status::OK;
    }

    // Otherwise, first we delete the corresponding unsequenced entry
    EntryHandle<LoggedCertificate> unseq_entry;
    const std::string hash(entry.Entry().Hash());
    status = GetPendingEntryForHash(hash, &unseq_entry);
    if (!status.ok()) {
      // Log a warning here, but don't bail on the clean up as we could just be
      // recovering from a crash halfway through a previous clean up.
      LOG(WARNING) << "Cleanup couldn't get unsequenced entry ("
                   << util::ToBase64(hash)
                   << ") corresponding to sequenced entry #" << sequence_number
                   << " : " << status;
    } else {
      status = DeleteEntry(&unseq_entry);
      if (!status.ok()) {
        LOG(WARNING) << "Cleanup couldn't delete unsequenced entry ("
                     << util::ToBase64(hash)
                     << ") corresponding to sequenced entry #"
                     << sequence_number << " : " << status;
        return status;
      }
    }
    VLOG(1) << "Cleanup deleted unsequenced entry (" << util::ToBase64(hash)
            << ") corresponding to sequenced entry #" << sequence_number;

    // Now delete the sequenced entry:
    status = DeleteEntry(&entry);
    if (!status.ok()) {
      LOG(WARNING) << "Cleanup couldn't delete sequenced entry #"
                   << sequence_number << " (but corresponding unsequenced "
                   << "entry was successfully deleted) : " << status;
      return status;
    }
    VLOG(1) << "Cleanup deleted sequenced entry #" << sequence_number;
  }
  return util::Status::OK;
}


}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_INL_H_
