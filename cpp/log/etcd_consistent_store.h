#ifndef CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_H_
#define CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_H_

#include <memory>
#include <stdint.h>
#include <vector>

#include "base/macros.h"
#include "proto/ct.pb.h"
#include "util/status.h"
#include "util/sync_etcd.h"

namespace cert_trans {

template <class Logged>
class EtcdConsistentStore;


// Wraps an instance of |T| and associates it with a versioning handle
// (required for atomic 'compare-and-update' semantics.)
template <class T>
class EntryHandle {
 public:
  EntryHandle() = default;
  EntryHandle(EntryHandle&& other) = default;

  const T& Entry() const;

  T* MutableEntry();

  bool HasHandle() const;

  int Handle() const;

 private:
  EntryHandle(const T& entry, int handle);

  EntryHandle(const T& entry);

  void Set(const T& entry, int handle);

  void SetHandle(int new_handle);

  T entry_;
  bool has_handle_;
  int handle_;

  template <class Logged>
  friend class EtcdConsistentStore;
  friend class EtcdConsistentStoreTest;

  DISALLOW_COPY_AND_ASSIGN(EntryHandle);
};


template <class Logged>
class EtcdConsistentStore {
 public:
  EtcdConsistentStore(SyncEtcdClient* client, const std::string& root,
                      const std::string& node_id);

  uint64_t NextAvailableSequenceNumber() const;

  util::Status SetServingSTH(const ct::SignedTreeHead& new_sth);

  util::Status AddPendingEntry(Logged* entry);

  util::Status GetPendingEntries(
      std::vector<EntryHandle<Logged>>* entries) const;

  util::Status GetSequencedEntries(
      std::vector<EntryHandle<Logged>>* entries) const;

  util::Status GetSequencedEntry(const uint64_t sequence_number,
                                 EntryHandle<Logged>* entry) const;

  util::Status AssignSequenceNumber(const uint64_t sequence_number,
                                    EntryHandle<Logged>* entry);

  util::Status SetClusterNodeState(const ct::ClusterNodeState& state);

 private:
  template <class T>
  util::Status GetEntry(const std::string& path, EntryHandle<T>* entry) const;

  template <class T>
  util::Status GetAllEntriesInDir(const std::string& dir,
                                  std::vector<EntryHandle<T>>* entries) const;

  template <class T>
  util::Status UpdateEntry(const std::string& path, EntryHandle<T>* entry);


  template <class T>
  util::Status CreateEntry(const std::string& path, EntryHandle<T>* entry);


  std::string GetFullPath(const std::string& key) const;

  SyncEtcdClient* const client_;
  const std::string root_;
  const std::string node_id_;

  DISALLOW_COPY_AND_ASSIGN(EtcdConsistentStore);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_ETCD_CONSISTENT_STORE_H_
