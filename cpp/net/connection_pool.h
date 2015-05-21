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


struct evhtp_connection_deleter {
  void operator()(evhtp_connection_t* con) const {
    evhtp_connection_free(con);
  }
};


typedef std::pair<std::string, uint16_t> HostPortPair;


class ConnectionPool {
 public:
  class Connection {
   public:
    evhtp_connection_t* connection() const {
      return conn_.get();
    }

    const HostPortPair& other_end() const;

   private:
    static evhtp_res ConnectionClosedHook(evhtp_connection_t* conn, void* arg);

    Connection(evhtp_connection_t* conn, HostPortPair&& other_end);

    std::unique_ptr<evhtp_connection_t, evhtp_connection_deleter> conn_;
    const HostPortPair other_end_;

    friend class ConnectionPool;
  };

  ConnectionPool(libevent::Base* base);

  std::unique_ptr<Connection> Get(const URL& url);
  void Put(std::unique_ptr<Connection>&& conn);

 private:
  void Cleanup();

  libevent::Base* const base_;

  std::mutex lock_;
  // We get and put connections from the back of the deque, and when
  // there are too many, we prune them from the front (LIFO).
  std::map<HostPortPair, std::deque<std::unique_ptr<Connection>>> conns_;
  bool cleanup_scheduled_;

  DISALLOW_COPY_AND_ASSIGN(ConnectionPool);
};


}  // namespace internal
}  // namespace cert_trans

#endif  // CERT_TRANS_NET_CONNECTION_POOL_H_
