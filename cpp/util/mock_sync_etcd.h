#ifndef CERT_TRANS_UTIL_MOCK_SYNC_ETCD_H_

#include <gmock/gmock.h>

#include "util/sync_etcd.h"

namespace cert_trans {


class MockSyncEtcdClient : public SyncEtcdClient {
 public:
  MockSyncEtcdClient() : SyncEtcdClient("host", 80) {
  }
  virtual ~MockSyncEtcdClient() = default;

  MOCK_METHOD3(Get, util::Status(const std::string& key, int* index,
                                 std::string* value));

  MOCK_METHOD2(GetAll,
               util::Status(const std::string& dir,
                            std::vector<std::pair<std::string, int>>* values));

  MOCK_METHOD3(Create, util::Status(const std::string& key,
                                    const std::string& value, int* index));

  MOCK_METHOD4(CreateInQueue,
               util::Status(const std::string& dir, const std::string& value,
                            std::string* key, int* index));

  MOCK_METHOD4(Update,
               util::Status(const std::string& key, const std::string& value,
                            const int previous_index, int* new_index));

  MOCK_METHOD3(ForceSet,
               util::Status(const std::string& key, const std::string& value,
                            int* new_index));

  MOCK_METHOD2(Delete,
               util::Status(const std::string& key, const int current_index));
};


}  // namespace cert_trans


#define CERT_TRANS_UTIL_MOCK_SYNC_ETCD_H_
#endif  // CERT_TRANS_UTIL_MOCK_SYNC_ETCD_H_
