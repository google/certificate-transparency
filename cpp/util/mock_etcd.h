#ifndef CERT_TRANS_UTIL_MOCK_ETCD_H_
#define CERT_TRANS_UTIL_MOCK_ETCD_H_

#include <gmock/gmock.h>

#include "util/etcd.h"

namespace cert_trans {


class MockEtcdClient : public EtcdClient {
 public:
  MOCK_METHOD3(Get,
               void(const Request& req, GetResponse* resp, util::Task* task));
  MOCK_METHOD4(Create, void(const std::string& key, const std::string& value,
                            Response* resp, util::Task* task));
  MOCK_METHOD5(CreateWithTTL,
               void(const std::string& key, const std::string& value,
                    const std::chrono::seconds& ttl, Response* resp,
                    util::Task* task));
  MOCK_METHOD5(Update, void(const std::string& key, const std::string& value,
                            const int64_t previous_index, Response* resp,
                            util::Task* task));
  MOCK_METHOD6(UpdateWithTTL,
               void(const std::string& key, const std::string& value,
                    const std::chrono::seconds& ttl,
                    const int64_t previous_index, Response* resp,
                    util::Task* task));
  MOCK_METHOD4(ForceSet, void(const std::string& key, const std::string& value,
                              Response* resp, util::Task* task));
  MOCK_METHOD5(ForceSetWithTTL,
               void(const std::string& key, const std::string& value,
                    const std::chrono::seconds& ttl, Response* resp,
                    util::Task* task));
  MOCK_METHOD3(Delete, void(const std::string& key,
                            const int64_t current_index, util::Task* task));
  MOCK_METHOD3(Watch, void(const std::string& key, const WatchCallback& cb,
                           util::Task* task));

  // TODO(pphaneuf): Shouldn't be used, and shouldn't be there, but
  // has to be for now.
  MOCK_METHOD5(Generic, void(const std::string& key,
                             const std::map<std::string, std::string>& params,
                             UrlFetcher::Verb verb, GenericResponse* resp,
                             util::Task* task));
};


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_MOCK_ETCD_H_
