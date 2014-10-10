#ifndef CERT_TRANS_UTIL_ETCD_H_
#define CERT_TRANS_UTIL_ETCD_H_

#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include <map>
#include <stdint.h>
#include <string>

#include "base/macros.h"
#include "util/json_wrapper.h"
#include "util/libevent_wrapper.h"

namespace cert_trans {


class EtcdClient {
 public:
  typedef boost::function<
      void(int status, const boost::shared_ptr<JsonObject>&)> GenericCallback;

  // TODO(pphaneuf): This should take a set of servers, not just one.
  static EtcdClient* Create(
      const boost::shared_ptr<libevent::Base>& event_base,
      const std::string& host, uint16_t port);

  virtual ~EtcdClient() {
  }

  // TODO(pphaneuf): This method should probably not be part of the
  // interface, but rather, there should be easy to use methods like
  // "Set", "Get", and so on.
  virtual void Generic(const std::string& key,
                       const std::map<std::string, std::string>& params,
                       evhttp_cmd_type verb, const GenericCallback& cb) = 0;

 protected:
  EtcdClient() {
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(EtcdClient);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_ETCD_H_
