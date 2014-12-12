#ifndef CERT_TRANS_UTIL_SYNC_ETCD_H_
#define CERT_TRANS_UTIL_SYNC_ETCD_H_

#include <chrono>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

#include "base/macros.h"
#include "util/etcd.h"

namespace util {
class Status;
}  // namespace util


namespace cert_trans {


// A synchronous wrapper around EtcdClient.
class SyncEtcdClient {
 public:
  // Contructs a new synchronous etcd client.
  // Note that SyncEtcdClient expects that someone is dispatching the event
  // loop underpinning |client|, but doesn't do that itself.
  // No change of ownership of |client|.
  SyncEtcdClient(EtcdClient* client);

  virtual ~SyncEtcdClient() = default;

  // Synchronous analogues to the etcd API below:

  virtual util::Status Get(const std::string& key, EtcdClient::Node* node);

  virtual util::Status GetAll(const std::string& dir,
                              std::vector<EtcdClient::Node>* values);

  virtual util::Status Create(const std::string& key, const std::string& value,
                              int64_t* index);

  virtual util::Status CreateWithTTL(const std::string& key,
                                     const std::string& value,
                                     const std::chrono::duration<int>& ttl,
                                     int64_t* index);

  virtual util::Status CreateInQueue(const std::string& dir,
                                     const std::string& value,
                                     std::string* key, int64_t* index);

  virtual util::Status Update(const std::string& key, const std::string& value,
                              const int64_t previous_index,
                              int64_t* new_index);

  virtual util::Status UpdateWithTTL(const std::string& key,
                                     const std::string& value,
                                     const std::chrono::duration<int>& ttl,
                                     const int64_t previous_index,
                                     int64_t* new_index);

  virtual util::Status ForceSet(const std::string& key,
                                const std::string& value, int64_t* new_index);

  virtual util::Status ForceSetWithTTL(const std::string& key,
                                       const std::string& value,
                                       const std::chrono::duration<int>& ttl,
                                       int64_t* new_index);

  virtual util::Status Delete(const std::string& key,
                              const int64_t current_index);

 private:
  EtcdClient* const client_;  // Not owned by us

  friend class SyncEtcdTest;

  DISALLOW_COPY_AND_ASSIGN(SyncEtcdClient);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_SYNC_ETCD_H_
