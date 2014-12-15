#ifndef CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_INL_H_
#define CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_INL_H_

#include <glog/logging.h>

#include "log/etcd_consistent_store.h"
#include "log/logged_certificate.h"
#include "util/util.h"

namespace cert_trans {
namespace {

// etcd path constants.
const char kUnsequencedDir[] = "/unsequenced/";
const char kSequencedDir[] = "/sequenced/";
const char kServingSthFile[] = "/serving_sth";
const char kNodesDir[] = "/nodes/";

}  // namespace


template <class Logged>
EtcdConsistentStore<Logged>::EtcdConsistentStore(EtcdClient* client,
                                                 const std::string& root,
                                                 const std::string& node_id)
    : client_(client), sync_client_(client), root_(root), node_id_(node_id) {
}


template <class Logged>
int64_t EtcdConsistentStore<Logged>::NextAvailableSequenceNumber() const {
  CHECK(false) << "Not Implemented";
  return 0;
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::SetServingSTH(
    const ct::SignedTreeHead& new_sth) {
  return util::Status(util::error::UNIMPLEMENTED, "Not implemented yet.");
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
    CHECK(preexisting_entry.Entry().entry() == entry->entry());
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
  // TODO(alcutter): These files should have an associated TTL.
  EntryHandle<ct::ClusterNodeState> entry(state);
  return ForceSetEntry(GetNodePath(node_id_), &entry);
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

}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_INL_H_
