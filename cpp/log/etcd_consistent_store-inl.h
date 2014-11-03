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


template <class T>
EntryHandle<T>::EntryHandle(const T& entry, int handle)
    : entry_(entry), has_handle_(true), handle_(handle) {
}


template <class T>
EntryHandle<T>::EntryHandle(const T& entry)
    : entry_(entry), has_handle_(false) {
}


template <class T>
const T& EntryHandle<T>::Entry() const {
  return entry_;
}


template <class T>
T* EntryHandle<T>::MutableEntry() {
  return &entry_;
}


template <class T>
bool EntryHandle<T>::HasHandle() const {
  return has_handle_;
}


template <class T>
int EntryHandle<T>::Handle() const {
  CHECK(has_handle_);
  return handle_;
}


template <class T>
void EntryHandle<T>::Set(const T& entry, int handle) {
  entry_ = entry;
  handle_ = handle;
  has_handle_ = true;
}


template <class T>
void EntryHandle<T>::SetHandle(int new_handle) {
  handle_ = new_handle;
  has_handle_ = true;
}


template <class Logged>
EtcdConsistentStore<Logged>::EtcdConsistentStore(SyncEtcdClient* client,
                                                 const std::string& root,
                                                 const std::string& node_id)
    : client_(client), root_(root), node_id_(node_id) {
}


template <class Logged>
uint64_t EtcdConsistentStore<Logged>::NextAvailableSequenceNumber() const {
  CHECK(false) << "Not Implemented";
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
  const std::string full_path(
      GetFullPath(kUnsequencedDir + util::ToBase64(entry->Hash())));
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
    const uint64_t sequence_number, EntryHandle<Logged>* entry) const {
  util::Status status(
      GetEntry(GetFullPath(kSequencedDir + std::to_string(sequence_number)),
               entry));
  if (status.ok()) {
    CHECK(entry->Entry().has_sequence_number());
  }

  return status;
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::AssignSequenceNumber(
    const uint64_t sequence_number, EntryHandle<Logged>* entry) {
  CHECK(!entry->Entry().has_sequence_number());
  return util::Status(util::error::UNIMPLEMENTED, "Not implemented yet.");
}


template <class Logged>
util::Status EtcdConsistentStore<Logged>::SetClusterNodeState(
    const ct::ClusterNodeState& state) {
  // TODO(alcutter): need a ForceUpdate (i.e. not compare-and-update)
  return util::Status(util::error::UNIMPLEMENTED, "Not implemented yet.");
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::GetEntry(
    const std::string& path, EntryHandle<T>* entry) const {
  CHECK_NOTNULL(entry);
  std::string flat_entry;
  int version;
  util::Status status(client_->Get(path, &version, &flat_entry));
  if (!status.ok()) {
    return status;
  }
  T t;
  CHECK(t.ParseFromString(flat_entry));
  entry->Set(t, version);
  return util::Status::OK;
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::GetAllEntriesInDir(
    const std::string& dir, std::vector<EntryHandle<T>>* entries) const {
  CHECK_NOTNULL(entries);
  CHECK_EQ(0, entries->size());
  std::vector<std::pair<std::string, int>> flat_entries;
  util::Status status(client_->GetAll(dir, &flat_entries));
  if (!status.ok()) {
    return status;
  }
  for (const auto& flat_entry : flat_entries) {
    T t;
    CHECK(t.ParseFromString(flat_entry.first));
    entries->emplace_back(EntryHandle<Logged>(t, flat_entry.second));
  }
  return util::Status::OK;
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::UpdateEntry(const std::string& path,
                                                      EntryHandle<T>* t) {
  std::string flat_entry;
  CHECK(t->SerializeToString(&flat_entry));
  int new_version;
  util::Status status(
      client_->Update(path, flat_entry, t->Handle(), &new_version));
  if (status.ok()) {
    t->SetHandle(new_version);
  }
  return status;
}


template <class Logged>
template <class T>
util::Status EtcdConsistentStore<Logged>::CreateEntry(const std::string& path,
                                                      EntryHandle<T>* t) {
  std::string flat_entry;
  CHECK(t->Entry().SerializeToString(&flat_entry));
  int new_version;
  util::Status status(client_->Create(path, flat_entry, &new_version));
  if (status.ok()) {
    t->SetHandle(new_version);
  }
  return status;
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
