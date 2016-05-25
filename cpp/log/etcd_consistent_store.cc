#include "log/etcd_consistent_store.h"

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <chrono>
#include <unordered_map>
#include <vector>

#include "base/notification.h"
#include "monitoring/event_metric.h"
#include "monitoring/latency.h"
#include "monitoring/monitoring.h"
#include "util/etcd_delete.h"
#include "util/executor.h"
#include "util/masterelection.h"
#include "util/util.h"

using ct::ClusterConfig;
using ct::ClusterNodeState;
using ct::SequenceMapping;
using ct::SignedTreeHead;
using std::bind;
using std::chrono::seconds;
using std::lock_guard;
using std::map;
using std::move;
using std::mutex;
using std::placeholders::_1;
using std::string;
using std::unique_lock;
using std::unique_ptr;
using std::vector;
using util::FromBase64;
using util::Status;
using util::StatusOr;
using util::SyncTask;
using util::Task;
using util::ToBase64;

// This needs to be quite frequent since the number of entries which can be
// added every second can be pretty high.
DEFINE_int32(etcd_stats_collection_interval_seconds, 2,
             "Number of seconds between fetches of etcd stats.");
DEFINE_int32(node_state_ttl_seconds, 60,
             "TTL in seconds on the node state files.");

namespace cert_trans {
namespace {

// etcd path constants.
const char kClusterConfigFile[] = "/cluster_config";
const char kEntriesDir[] = "/entries/";
const char kSequenceFile[] = "/sequence_mapping";
const char kServingSthFile[] = "/serving_sth";
const char kNodesDir[] = "/nodes/";


static Gauge<string>* etcd_total_entries =
    Gauge<string>::New("etcd_total_entries", "type",
                       "Total number of entries in etcd by type.");

static Gauge<string>* etcd_store_stats =
    Gauge<string>::New("etcd_store_stats", "name",
                       "Re-export of etcd's store stats.");

static EventMetric<string> etcd_throttle_delay_ms("etcd_throttle_delay_ms",
                                                  "type",
                                                  "Count and total thottle "
                                                  "delay applied to requests, "
                                                  "broken down by request "
                                                  "type");

static Counter<string>* etcd_rejected_requests =
    Counter<string>::New("etcd_rejected_requests", "type",
                         "Total number of requests rejected due to overload, "
                         "broken down by request type.");

static Latency<std::chrono::milliseconds, string> etcd_latency_by_op_ms(
    "etcd_latency_by_op_ms", "operation",
    "Etcd latency in ms broken down by operation.");


// TODO(pphaneuf): Hmm, I think this should check that it's not just
// ordered, but contiguous?
void CheckMappingIsOrdered(const SequenceMapping& mapping) {
  if (mapping.mapping_size() < 2) {
    return;
  }
  for (int64_t i = 0; i < mapping.mapping_size() - 1; ++i) {
    CHECK_LT(mapping.mapping(i).sequence_number(),
             mapping.mapping(i + 1).sequence_number());
  }
}


StatusOr<int64_t> GetStat(const map<string, int64_t>& stats,
                          const string& name) {
  const auto& it(stats.find(name));
  if (it == stats.end()) {
    return Status(util::error::FAILED_PRECONDITION, name + " missing.");
  }
  return it->second;
}


StatusOr<int64_t> CalculateNumEtcdEntries(const map<string, int64_t>& stats) {
  StatusOr<int64_t> created(GetStat(stats, "createSuccess"));
  if (!created.ok()) {
    return created;
  }

  StatusOr<int64_t> deleted(GetStat(stats, "deleteSuccess"));
  if (!deleted.ok()) {
    return deleted;
  }

  StatusOr<int64_t> compareDeleted(GetStat(stats, "compareAndDeleteSuccess"));
  if (!compareDeleted.ok()) {
    return compareDeleted;
  }
  StatusOr<int64_t> expired(GetStat(stats, "expireCount"));
  if (!expired.ok()) {
    return expired;
  }

  const int64_t num_removed(deleted.ValueOrDie() +
                            compareDeleted.ValueOrDie() +
                            expired.ValueOrDie());
  return created.ValueOrDie() - num_removed;
}

}  // namespace


EtcdConsistentStore::EtcdConsistentStore(
    libevent::Base* base, util::Executor* executor, EtcdClient* client,
    const MasterElection* election, const string& root, const string& node_id)
    : client_(CHECK_NOTNULL(client)),
      base_(CHECK_NOTNULL(base)),
      executor_(CHECK_NOTNULL(executor)),
      election_(CHECK_NOTNULL(election)),
      root_(root),
      node_id_(node_id),
      serving_sth_watch_task_(CHECK_NOTNULL(executor)),
      cluster_config_watch_task_(CHECK_NOTNULL(executor)),
      etcd_stats_task_(executor_),
      received_initial_sth_(false),
      exiting_(false),
      num_etcd_entries_(0) {
  // Set up watches on things we're interested in...
  WatchServingSTH(bind(&EtcdConsistentStore::OnEtcdServingSTHUpdated, this,
                       _1),
                  serving_sth_watch_task_.task());
  WatchClusterConfig(bind(&EtcdConsistentStore::OnClusterConfigUpdated, this,
                          _1),
                     cluster_config_watch_task_.task());

  StartEtcdStatsFetch();

  // And wait for the initial updates to come back so that we've got a
  // view on the current state before proceding...
  {
    unique_lock<mutex> lock(mutex_);
    serving_sth_cv_.wait(lock, [this]() { return received_initial_sth_; });
  }
}


EtcdConsistentStore::~EtcdConsistentStore() {
  VLOG(1) << "Cancelling watch tasks.";
  serving_sth_watch_task_.Cancel();
  cluster_config_watch_task_.Cancel();
  VLOG(1) << "Waiting for watch tasks to return.";
  serving_sth_watch_task_.Wait();
  cluster_config_watch_task_.Wait();
  VLOG(1) << "Cancelling stats task.";
  etcd_stats_task_.Cancel();
  etcd_stats_task_.Wait();
  VLOG(1) << "Joining cleanup thread";
  {
    lock_guard<mutex> lock(mutex_);
    exiting_ = true;
  }
  serving_sth_cv_.notify_all();
}


StatusOr<int64_t> EtcdConsistentStore::NextAvailableSequenceNumber() const {
  ScopedLatency scoped_latency(etcd_latency_by_op_ms.GetScopedLatency(
      "next_available_sequence_number"));

  EntryHandle<SequenceMapping> sequence_mapping;
  Status status(GetSequenceMapping(&sequence_mapping));
  if (!status.ok()) {
    return status;
  }
  etcd_total_entries->Set("sequenced",
                          sequence_mapping.Entry().mapping_size());
  if (sequence_mapping.Entry().mapping_size() > 0) {
    return sequence_mapping.Entry()
               .mapping(sequence_mapping.Entry().mapping_size() - 1)
               .sequence_number() +
           1;
  }

  if (!serving_sth_) {
    LOG(WARNING) << "Log has no Serving STH [new log?], returning 0";
    return 0;
  }

  return serving_sth_->Entry().tree_size();
}


void EtcdConsistentStore::WaitForServingSTHVersion(unique_lock<mutex>* lock,
                                                   const int version) {
  VLOG(1) << "Waiting for ServingSTH version " << version;
  serving_sth_cv_.wait(*lock, [this, version]() {
    VLOG(1) << "Want version " << version << ", have: "
            << (serving_sth_ ? std::to_string(serving_sth_->Handle())
                             : "none");
    return serving_sth_ && serving_sth_->Handle() >= version;
  });
}


Status EtcdConsistentStore::SetServingSTH(const SignedTreeHead& new_sth) {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("set_serving_sth"));

  const string full_path(GetFullPath(kServingSthFile));
  unique_lock<mutex> lock(mutex_);

  // The watcher should have already populated serving_sth_ if etcd had one.
  if (!serving_sth_) {
    // Looks like we're creating the first ever serving_sth!
    LOG(WARNING) << "Creating new " << full_path;
    // There's no current serving STH, so we can try to create one.
    EntryHandle<SignedTreeHead> sth_handle(full_path, new_sth);
    Status status(CreateEntry(&sth_handle));
    if (!status.ok()) {
      return status;
    }
    WaitForServingSTHVersion(&lock, sth_handle.Handle());
    return Status::OK;
  }

  // Looks like we're updating an existing serving_sth.
  // First check that we're not trying to overwrite it with itself or an older
  // one:
  if (serving_sth_->Entry().timestamp() >= new_sth.timestamp()) {
    return Status(util::error::OUT_OF_RANGE,
                  "Tree head is not newer than existing head");
  }

  // Ensure that nothing weird is going on with the tree size:
  CHECK_LE(serving_sth_->Entry().tree_size(), new_sth.tree_size());

  VLOG(1) << "Updating existing " << full_path;
  EntryHandle<SignedTreeHead> sth_to_etcd(full_path, new_sth,
                                          serving_sth_->Handle());
  Status status(UpdateEntry(&sth_to_etcd));
  if (!status.ok()) {
    return status;
  }
  WaitForServingSTHVersion(&lock, sth_to_etcd.Handle());
  return Status::OK;
}


StatusOr<SignedTreeHead> EtcdConsistentStore::GetServingSTH() const {
  lock_guard<mutex> lock(mutex_);
  if (serving_sth_) {
    return serving_sth_->Entry();
  } else {
    return Status(util::error::NOT_FOUND, "No current Serving STH.");
  }
}


bool LeafEntriesMatch(const LoggedEntry& a, const LoggedEntry& b) {
  CHECK_EQ(a.entry().type(), b.entry().type());
  switch (a.entry().type()) {
    case ct::X509_ENTRY:
      return a.entry().x509_entry().leaf_certificate() ==
             b.entry().x509_entry().leaf_certificate();
    case ct::PRECERT_ENTRY:
      return a.entry().precert_entry().pre_certificate() ==
             b.entry().precert_entry().pre_certificate();
    case ct::PRECERT_ENTRY_V2:
      // TODO(mhs): V2 implementation required here
      LOG(FATAL) << "CT V2 not yet implemented";
      break;
    case ct::X_JSON_ENTRY:
      return a.entry().x_json_entry().json() ==
             b.entry().x_json_entry().json();
    case ct::UNKNOWN_ENTRY_TYPE:
      // Handle it below.
      break;
  }
  LOG(FATAL) << "Encountered UNKNOWN_ENTRY_TYPE:\n" << a.entry().DebugString();
}


Status EtcdConsistentStore::AddPendingEntry(LoggedEntry* entry) {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("add_pending_entry"));

  CHECK_NOTNULL(entry);
  CHECK(!entry->has_sequence_number());

  Status status(MaybeReject("add_pending_entry"));
  if (!status.ok()) {
    return status;
  }

  const string full_path(GetEntryPath(*entry));
  EntryHandle<LoggedEntry> handle(full_path, *entry);
  status = CreateEntry(&handle);
  if (status.CanonicalCode() == util::error::FAILED_PRECONDITION) {
    // Entry with that hash already exists.
    EntryHandle<LoggedEntry> preexisting_entry;
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
    return Status(util::error::ALREADY_EXISTS,
                  "Pending entry already exists.");
  }
  return status;
}


Status EtcdConsistentStore::GetPendingEntryForHash(
    const string& hash, EntryHandle<LoggedEntry>* entry) const {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("get_pending_entry_for_hash"));

  Status status(GetEntry(GetEntryPath(hash), entry));
  if (status.ok()) {
    CHECK(!entry->Entry().has_sequence_number());
  }

  return status;
}


Status EtcdConsistentStore::GetPendingEntries(
    vector<EntryHandle<LoggedEntry>>* entries) const {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("get_pending_entries"));

  Status status(GetAllEntriesInDir(GetFullPath(kEntriesDir), entries));
  if (status.ok()) {
    for (const auto& entry : *entries) {
      CHECK(!entry.Entry().has_sequence_number());
    }
  }
  etcd_total_entries->Set("entries", entries->size());
  return status;
}


Status EtcdConsistentStore::GetSequenceMapping(
    EntryHandle<SequenceMapping>* sequence_mapping) const {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("get_sequence_mapping"));

  Status status(GetEntry(GetFullPath(kSequenceFile), sequence_mapping));
  if (!status.ok()) {
    return status;
  }
  CheckMappingIsOrdered(sequence_mapping->Entry());
  CheckMappingIsContiguousWithServingTree(sequence_mapping->Entry());
  etcd_total_entries->Set("sequenced",
                          sequence_mapping->Entry().mapping_size());
  return Status::OK;
}


Status EtcdConsistentStore::UpdateSequenceMapping(
    EntryHandle<SequenceMapping>* entry) {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("update_sequence_mapping"));

  CHECK(entry->HasHandle());
  CheckMappingIsOrdered(entry->Entry());
  CheckMappingIsContiguousWithServingTree(entry->Entry());
  return UpdateEntry(entry);
}


StatusOr<ClusterNodeState> EtcdConsistentStore::GetClusterNodeState() const {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("get_cluster_node_state"));

  EntryHandle<ClusterNodeState> handle;
  Status status(GetEntry(GetNodePath(node_id_), &handle));
  if (!status.ok()) {
    return status;
  }
  return handle.Entry();
}


Status EtcdConsistentStore::SetClusterNodeState(
    const ClusterNodeState& state) {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("set_cluster_node_state"));

  // TODO(alcutter): consider keeping the handle for this around to check that
  // nobody else is updating our cluster state.
  ClusterNodeState local_state(state);
  local_state.set_node_id(node_id_);
  EntryHandle<ClusterNodeState> entry(GetNodePath(node_id_), local_state);
  const seconds ttl(FLAGS_node_state_ttl_seconds);
  return ForceSetEntryWithTTL(ttl, &entry);
}


// static
template <class T, class CB>
void EtcdConsistentStore::ConvertSingleUpdate(
    const string& full_path, const CB& callback,
    const vector<EtcdClient::Node>& updates) {
  CHECK_LE(static_cast<size_t>(0), updates.size());
  if (updates.empty()) {
    EntryHandle<T> handle;
    handle.SetKey(full_path);
    callback(Update<T>(handle, false /* exists */));
  } else {
    callback(TypedUpdateFromNode<T>(updates[0]));
  }
}


// static
template <class T, class CB>
void EtcdConsistentStore::ConvertMultipleUpdate(
    const CB& callback, const vector<EtcdClient::Node>& watch_updates) {
  vector<Update<T>> updates;
  for (auto& w : watch_updates) {
    updates.emplace_back(TypedUpdateFromNode<T>(w));
  }
  callback(updates);
}


void EtcdConsistentStore::WatchServingSTH(
    const ConsistentStore::ServingSTHCallback& cb, Task* task) {
  const string full_path(GetFullPath(kServingSthFile));
  client_->Watch(full_path,
                 bind(&ConvertSingleUpdate<
                          SignedTreeHead, ConsistentStore::ServingSTHCallback>,
                      full_path, cb, _1),
                 task);
}


void EtcdConsistentStore::WatchClusterNodeStates(
    const ConsistentStore::ClusterNodeStateCallback& cb, Task* task) {
  client_->Watch(
      GetFullPath(kNodesDir),
      bind(&ConvertMultipleUpdate<ClusterNodeState,
                                  ConsistentStore::ClusterNodeStateCallback>,
           cb, _1),
      task);
}


void EtcdConsistentStore::WatchClusterConfig(
    const ConsistentStore::ClusterConfigCallback& cb, Task* task) {
  const string full_path(GetFullPath(kClusterConfigFile));
  client_->Watch(
      full_path,
      bind(&ConvertSingleUpdate<ClusterConfig,
                                ConsistentStore::ClusterConfigCallback>,
           full_path, cb, _1),
      task);
}


Status EtcdConsistentStore::SetClusterConfig(const ClusterConfig& config) {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("set_cluster_config"));

  EntryHandle<ClusterConfig> entry(GetFullPath(kClusterConfigFile), config);
  return ForceSetEntry(&entry);
}


template <class T>
Status EtcdConsistentStore::GetEntry(const string& path,
                                     EntryHandle<T>* entry) const {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("get_entry"));

  CHECK_NOTNULL(entry);
  SyncTask task(executor_);
  EtcdClient::GetResponse resp;
  client_->Get(path, &resp, task.task());
  task.Wait();
  if (!task.status().ok()) {
    return task.status();
  }
  T t;
  CHECK(t.ParseFromString(FromBase64(resp.node.value_.c_str())));
  entry->Set(path, t, resp.node.modified_index_);
  return Status::OK;
}


Status EtcdConsistentStore::GetAllEntriesInDir(
    const string& dir, vector<EntryHandle<LoggedEntry>>* entries) const {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("get_all_entries_in_dir"));

  CHECK_NOTNULL(entries);
  CHECK_EQ(static_cast<size_t>(0), entries->size());
  SyncTask task(executor_);
  EtcdClient::GetResponse resp;
  client_->Get(dir, &resp, task.task());
  task.Wait();
  if (!task.status().ok()) {
    return task.status();
  }
  if (!resp.node.is_dir_) {
    return Status(util::error::FAILED_PRECONDITION,
                  "node is not a directory: " + dir);
  }
  for (const auto& node : resp.node.nodes_) {
    LoggedEntry entry;
    CHECK(entry.ParseFromString(FromBase64(node.value_.c_str())));
    entries->emplace_back(
        EntryHandle<LoggedEntry>(node.key_, entry, node.modified_index_));
  }
  return Status::OK;
}


Status EtcdConsistentStore::UpdateEntry(EntryHandleBase* t) {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("update_entry"));

  CHECK_NOTNULL(t);
  CHECK(t->HasHandle());
  CHECK(t->HasKey());
  string flat_entry;
  CHECK(t->SerializeToString(&flat_entry));
  SyncTask task(executor_);
  EtcdClient::Response resp;
  client_->Update(t->Key(), ToBase64(flat_entry), t->Handle(), &resp,
                  task.task());
  task.Wait();
  if (task.status().ok()) {
    t->SetHandle(resp.etcd_index);
  }
  return task.status();
}


Status EtcdConsistentStore::CreateEntry(EntryHandleBase* t) {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("create_entry"));

  CHECK_NOTNULL(t);
  CHECK(!t->HasHandle());
  CHECK(t->HasKey());
  string flat_entry;
  CHECK(t->SerializeToString(&flat_entry));
  SyncTask task(executor_);
  EtcdClient::Response resp;
  client_->Create(t->Key(), ToBase64(flat_entry), &resp, task.task());
  task.Wait();
  if (task.status().ok()) {
    t->SetHandle(resp.etcd_index);
  }
  return task.status();
}


Status EtcdConsistentStore::ForceSetEntry(EntryHandleBase* t) {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("force_set_entry"));

  CHECK_NOTNULL(t);
  CHECK(t->HasKey());
  // For now we check that |t| wasn't fetched from the etcd store (i.e. it's a
  // new EntryHandle.  The reason is that if it had been fetched, then the
  // calling code should be doing an UpdateEntry() here since they have the
  // handle.
  CHECK(!t->HasHandle());
  string flat_entry;
  CHECK(t->SerializeToString(&flat_entry));
  SyncTask task(executor_);
  EtcdClient::Response resp;
  client_->ForceSet(t->Key(), ToBase64(flat_entry), &resp, task.task());
  task.Wait();
  if (task.status().ok()) {
    t->SetHandle(resp.etcd_index);
  }
  return task.status();
}


Status EtcdConsistentStore::ForceSetEntryWithTTL(const seconds& ttl,
                                                 EntryHandleBase* t) {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("force_set_entry_with_ttl"));

  CHECK_NOTNULL(t);
  CHECK(t->HasKey());
  // For now we check that |t| wasn't fetched from the etcd store (i.e. it's a
  // new EntryHandle.  The reason is that if it had been fetched, then the
  // calling code should be doing an UpdateEntryWithTTL() here since they have
  // the handle.
  CHECK(!t->HasHandle());
  CHECK_LE(0, ttl.count());
  string flat_entry;
  CHECK(t->SerializeToString(&flat_entry));
  SyncTask task(executor_);
  EtcdClient::Response resp;
  client_->ForceSetWithTTL(t->Key(), ToBase64(flat_entry), ttl, &resp,
                           task.task());
  task.Wait();
  if (task.status().ok()) {
    t->SetHandle(resp.etcd_index);
  }
  return task.status();
}


Status EtcdConsistentStore::DeleteEntry(const EntryHandleBase& entry) {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("delete_entry"));

  CHECK(entry.HasHandle());
  CHECK(entry.HasKey());
  SyncTask task(executor_);
  client_->Delete(entry.Key(), entry.Handle(), task.task());
  task.Wait();
  return task.status();
}


string EtcdConsistentStore::GetEntryPath(const LoggedEntry& entry) const {
  return GetEntryPath(entry.Hash());
}


string EtcdConsistentStore::GetEntryPath(const string& hash) const {
  return GetFullPath(string(kEntriesDir) + util::HexString(hash));
}


string EtcdConsistentStore::GetNodePath(const string& id) const {
  return GetFullPath(string(kNodesDir) + id);
}


string EtcdConsistentStore::GetFullPath(const string& key) const {
  CHECK(key.size() > 0);
  CHECK_EQ('/', key[0]);
  return root_ + key;
}


void EtcdConsistentStore::CheckMappingIsContiguousWithServingTree(
    const SequenceMapping& mapping) const {
  lock_guard<mutex> lock(mutex_);
  if (serving_sth_ && mapping.mapping_size() > 0) {
    // The sequence numbers are signed. However the tree size must fit in
    // memory so the unsigned -> signed conversion below should not overflow.
    CHECK_LE(serving_sth_->Entry().tree_size(), INT64_MAX);

    const int64_t tree_size(serving_sth_->Entry().tree_size());
    // The mapping must not have a gap between its lowest mapping and the
    // serving tree
    const int64_t lowest_sequence_number(mapping.mapping(0).sequence_number());
    CHECK_LE(lowest_sequence_number, tree_size);
    // It must also be contiguous for all entries not yet included in the
    // serving tree. (Note that entries below that may not be contiguous
    // because the clean-up operation may not remove them in order.)
    bool above_sth(false);
    for (int i(0); i < mapping.mapping_size() - 1; ++i) {
      const int64_t mapped_seq(mapping.mapping(i).sequence_number());
      if (mapped_seq >= tree_size) {
        CHECK_EQ(mapped_seq + 1, mapping.mapping(i + 1).sequence_number());
        above_sth = true;
      } else {
        CHECK(!above_sth);
      }
    }
  }
}


// static
template <class T>
Update<T> EtcdConsistentStore::TypedUpdateFromNode(
    const EtcdClient::Node& node) {
  const string raw_value(FromBase64(node.value_.c_str()));
  T thing;
  CHECK(thing.ParseFromString(raw_value)) << raw_value;
  EntryHandle<T> handle(node.key_, thing);
  if (!node.deleted_) {
    handle.SetHandle(node.modified_index_);
  }
  return Update<T>(handle, !node.deleted_);
}


void EtcdConsistentStore::UpdateLocalServingSTH(
    const unique_lock<mutex>& lock,
    const EntryHandle<SignedTreeHead>& handle) {
  CHECK(lock.owns_lock());
  CHECK(!serving_sth_ ||
        serving_sth_->Entry().timestamp() < handle.Entry().timestamp());

  VLOG(1) << "Updating serving_sth_ to: " << handle.Entry().DebugString();
  serving_sth_.reset(new EntryHandle<SignedTreeHead>(handle));
}


void EtcdConsistentStore::OnEtcdServingSTHUpdated(
    const Update<SignedTreeHead>& update) {
  unique_lock<mutex> lock(mutex_);

  if (update.exists_) {
    VLOG(1) << "Got ServingSTH version " << update.handle_.Handle() << ": "
            << update.handle_.Entry().DebugString();
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


void EtcdConsistentStore::OnClusterConfigUpdated(
    const Update<ClusterConfig>& update) {
  if (update.exists_) {
    VLOG(1) << "Got ClusterConfig version " << update.handle_.Handle() << ": "
            << update.handle_.Entry().DebugString();
    lock_guard<mutex> lock(mutex_);
    cluster_config_.reset(new ClusterConfig(update.handle_.Entry()));
  } else {
    LOG(WARNING) << "ClusterConfig non-existent/deleted.";
    // TODO(alcutter): What to do here?
  }
}


StatusOr<int64_t> EtcdConsistentStore::CleanupOldEntries() {
  ScopedLatency scoped_latency(
      etcd_latency_by_op_ms.GetScopedLatency("cleanup_old_entries"));

  if (!election_->IsMaster()) {
    return Status(util::error::PERMISSION_DENIED,
                  "Non-master node cannot run cleanups.");
  }

  // Figure out where we're cleaning up to...
  unique_lock<mutex> lock(mutex_);
  if (!serving_sth_) {
    LOG(INFO) << "No current serving_sth, nothing to do.";
    return 0;
  }
  const int64_t clean_up_to_sequence_number(serving_sth_->Entry().tree_size() -
                                            1);
  lock.unlock();

  LOG(INFO) << "Cleaning old entries up to and including sequence number: "
            << clean_up_to_sequence_number;

  EntryHandle<SequenceMapping> sequence_mapping;
  Status status(GetSequenceMapping(&sequence_mapping));
  if (!status.ok()) {
    LOG(WARNING) << "Couldn't get sequence mapping: " << status;
    return status;
  }

  vector<string> keys_to_delete;
  for (int mapping_index = 0;
       mapping_index < sequence_mapping.Entry().mapping_size() &&
       sequence_mapping.Entry().mapping(mapping_index).sequence_number() <=
           clean_up_to_sequence_number;
       ++mapping_index) {
    // Delete the entry from /entries.
    keys_to_delete.emplace_back(GetEntryPath(
        sequence_mapping.Entry().mapping(mapping_index).entry_hash()));
  }


  const int64_t num_entries_cleaned(keys_to_delete.size());
  SyncTask task(executor_);
  EtcdForceDeleteKeys(client_, move(keys_to_delete), task.task());
  task.Wait();
  status = task.status();
  if (!status.ok()) {
    LOG(WARNING) << "EtcdDeleteKeys failed: " << task.status();
  }
  return num_entries_cleaned;
}


void EtcdConsistentStore::StartEtcdStatsFetch() {
  if (etcd_stats_task_.task()->CancelRequested()) {
    etcd_stats_task_.task()->Return(Status::CANCELLED);
    return;
  }
  EtcdClient::StatsResponse* response(new EtcdClient::StatsResponse);
  Task* stats_task(etcd_stats_task_.task()->AddChild(
      bind(&EtcdConsistentStore::EtcdStatsFetchDone, this, response, _1)));
  client_->GetStoreStats(response, stats_task);
}


void EtcdConsistentStore::EtcdStatsFetchDone(
    EtcdClient::StatsResponse* response, Task* task) {
  CHECK_NOTNULL(response);
  CHECK_NOTNULL(task);
  unique_ptr<EtcdClient::StatsResponse> response_deleter(response);
  if (task->status().ok()) {
    for (const auto& stat : response->stats) {
      VLOG(2) << "etcd stat: " << stat.first << " = " << stat.second;
      etcd_store_stats->Set(stat.first, stat.second);
    }
    const StatusOr<int64_t> num_entries(
        CalculateNumEtcdEntries(response->stats));
    if (num_entries.ok()) {
      {
        lock_guard<mutex> lock(mutex_);
        num_etcd_entries_ = num_entries.ValueOrDie();
      }
      etcd_total_entries->Set("all", num_etcd_entries_);
    } else {
      VLOG(1) << "Failed to calculate num_entries: " << num_entries.status();
    }
  } else {
    LOG(WARNING) << "Etcd stats fetch failed: " << task->status();
  }

  base_->Delay(seconds(FLAGS_etcd_stats_collection_interval_seconds),
               etcd_stats_task_.task()->AddChild(
                   bind(&EtcdConsistentStore::StartEtcdStatsFetch, this)));
}

// This method attempts to modulate the incoming traffic in response to the
// number of entries currently in etcd.
//
// Once the number of entries is above reject_threshold, we will start
// returning a RESOURCE_EXHAUSTED status, which should result in a 503 being
// sent to the client.
Status EtcdConsistentStore::MaybeReject(const string& type) const {
  unique_lock<mutex> lock(mutex_);

  if (!cluster_config_) {
    // No config, whatever.
    return Status::OK;
  }

  const int64_t etcd_size(num_etcd_entries_);
  const int64_t reject_threshold(
      cluster_config_->etcd_reject_add_pending_threshold());
  lock.unlock();

  if (etcd_size >= reject_threshold) {
    etcd_rejected_requests->Increment(type);
    return Status(util::error::RESOURCE_EXHAUSTED,
                  "Rejected due to high number of pending entries.");
  }
  return Status::OK;
}


}  // namespace cert_trans
