#ifndef CERT_TRANS_NET_CONNECTION_POOL_H_
#define CERT_TRANS_NET_CONNECTION_POOL_H_

#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <stdint.h>
#include <string>

#include "base/macros.h"
#include "net/url.h"
#include "util/libevent_wrapper.h"

namespace cert_trans {
namespace internal {


struct evhttp_connection_deleter {
  void operator()(evhttp_connection* conn) const {
    evhttp_connection_free(conn);
  }
};


typedef std::unique_ptr<evhttp_connection, evhttp_connection_deleter>
    evhttp_connection_unique_ptr;


class ConnectionPool {
 public:
  ConnectionPool(libevent::Base* base);

  evhttp_connection_unique_ptr Get(const URL& url);
  void Put(evhttp_connection_unique_ptr&& conn);

 private:
  typedef std::pair<std::string, uint16_t> HostPortPair;

  libevent::Base* const base_;

  std::mutex lock_;
  // We get and put connections from the back of the deque, and when
  // there are too many, we prune them from the front (LIFO).
  std::map<HostPortPair, std::deque<evhttp_connection_unique_ptr>> conns_;

  DISALLOW_COPY_AND_ASSIGN(ConnectionPool);
};


}  // namespace internal
}  // namespace cert_trans

#endif  // CERT_TRANS_NET_CONNECTION_POOL_H_
