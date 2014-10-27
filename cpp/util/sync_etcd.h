#ifndef CERT_TRANS_UTIL_SYNC_ETCD_H_
#define CERT_TRANS_UTIL_SYNC_ETCD_H_

#include <boost/shared_ptr.hpp>
#include <stdint.h>
#include <string>
#include <list>

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

  // Synchronous analogues to the etcd API below:

  util::Status Get(const std::string& key, int* index, std::string* value);

  util::Status GetAll(const std::string& dir,
                      std::list<std::pair<std::string, int> >* values);

  util::Status Create(const std::string& key, const std::string& value,
                      int* index);

  util::Status CreateInQueue(const std::string& dir, const std::string& value,
                             std::string* key, int* index);

  util::Status Update(const std::string& key, const std::string& value,
                      const int previous_index, int* new_index);

  util::Status Delete(const std::string& key, const int current_index);

 private:
  // Testing only
  // Takes ownership of |client_|
  SyncEtcdClient(EtcdClient* client_);

  boost::shared_ptr<libevent::Base> base_;
  boost::scoped_ptr<EtcdClient> client_;

  friend class SyncEtcdTest;

  DISALLOW_COPY_AND_ASSIGN(SyncEtcdClient);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_SYNC_ETCD_H_
