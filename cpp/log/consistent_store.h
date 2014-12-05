#ifndef CERT_TRANS_LOG_CONSISTENT_STORE_H_
#define CERT_TRANS_LOG_CONSISTENT_STORE_H_

#include <stdint.h>
#include <vector>

#include "base/macros.h"
#include "util/status.h"

namespace ct {

class ClusterNodeState;
class SignedTreeHead;

}  // namespace ct;


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

  EntryHandle& operator=(EntryHandle&& other) = default;

  const T& Entry() const {
    return entry_;
  }

  T* MutableEntry() {
    return &entry_;
  }

  bool HasHandle() const {
    return has_handle_;
  }

  int Handle() const {
    return handle_;
  }

 private:
  EntryHandle(const T& entry, int handle)
      : entry_(entry), has_handle_(true), handle_(handle) {
  }

  explicit EntryHandle(const T& entry) : entry_(entry), has_handle_(false) {
  }

  void Set(const T& entry, int handle) {
    entry_ = entry;
    handle_ = handle;
    has_handle_ = true;
  }

  void SetHandle(int new_handle) {
    handle_ = new_handle;
    has_handle_ = true;
  }

  T entry_;
  bool has_handle_;
  int handle_;

  template <class Logged>
  friend class EtcdConsistentStore;
  friend class EtcdConsistentStoreTest;
  template <class Logged>
  friend class FakeConsistentStore;
  friend class FakeConsistentStoreTest;

  DISALLOW_COPY_AND_ASSIGN(EntryHandle);
};


template <class Logged>
class ConsistentStore {
 public:
  ConsistentStore() = default;

  virtual int64_t NextAvailableSequenceNumber() const = 0;

  virtual util::Status SetServingSTH(const ct::SignedTreeHead& new_sth) = 0;

  virtual util::Status AddPendingEntry(Logged* entry) = 0;

  virtual util::Status GetPendingEntryForHash(
      const std::string& hash, EntryHandle<Logged>* entry) const = 0;

  virtual util::Status GetPendingEntries(
      std::vector<EntryHandle<Logged>>* entries) const = 0;

  virtual util::Status GetSequencedEntries(
      std::vector<EntryHandle<Logged>>* entries) const = 0;

  virtual util::Status GetSequencedEntry(const int64_t sequence_number,
                                         EntryHandle<Logged>* entry) const = 0;

  virtual util::Status AssignSequenceNumber(const int64_t sequence_number,
                                            EntryHandle<Logged>* entry) = 0;

  virtual util::Status SetClusterNodeState(
      const ct::ClusterNodeState& state) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(ConsistentStore);
};


}  // namespace

#endif  // CERT_TRANS_LOG_CONSISTENT_STORE_H_
