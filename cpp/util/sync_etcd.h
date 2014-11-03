#ifndef CERT_TRANS_UTIL_SYNC_ETCD_H_
#define CERT_TRANS_UTIL_SYNC_ETCD_H_

#include <vector>
#include <memory>
#include <stdint.h>
#include <string>

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
  SyncEtcdClient(const std::string& host, uint16_t port);

  virtual ~SyncEtcdClient() = default;

  // Synchronous analogues to the etcd API below:

  virtual util::Status Get(const std::string& key, int* index,
                           std::string* value);

  virtual util::Status GetAll(
      const std::string& dir,
      std::vector<std::pair<std::string, int> >* values);

  virtual util::Status Create(const std::string& key, const std::string& value,
                              int* index);

  virtual util::Status CreateInQueue(const std::string& dir,
                                     const std::string& value,
                                     std::string* key, int* index);

  virtual util::Status Update(const std::string& key, const std::string& value,
                              const int previous_index, int* new_index);

  virtual util::Status Delete(const std::string& key, const int current_index);

 private:
  // Testing only
  // Takes ownership of |client_|
  SyncEtcdClient(EtcdClient* client_);

  std::shared_ptr<libevent::Base> base_;
  std::unique_ptr<EtcdClient> client_;

  friend class SyncEtcdTest;

  DISALLOW_COPY_AND_ASSIGN(SyncEtcdClient);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_SYNC_ETCD_H_
