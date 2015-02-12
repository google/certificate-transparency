#include "net/connection_pool.h"

#include <glog/logging.h>

using std::lock_guard;
using std::move;
using std::mutex;
using std::pair;
using std::string;

DEFINE_int32(url_fetcher_max_conn_per_host_port, 4,
             "maximum number of URL fetcher connections per host:port");

namespace cert_trans {
namespace internal {

ConnectionPool::ConnectionPool(libevent::Base* base)
    : base_(CHECK_NOTNULL(base)) {
}


evhttp_connection_unique_ptr ConnectionPool::Get(const URL& url) {
  // TODO(pphaneuf): Add support for other protocols.
  CHECK_EQ(url.Protocol(), "http");
  const HostPortPair key(url.Host(), url.Port() != 0 ? url.Port() : 80);
  lock_guard<mutex> lock(lock_);

  auto it(conns_.find(key));
  if (it == conns_.end()) {
    return evhttp_connection_unique_ptr(
        base_->HttpConnectionNew(key.first, key.second));
  }

  evhttp_connection_unique_ptr retval(move(it->second.back()));
  it->second.pop_back();

  return retval;
}


void ConnectionPool::Put(evhttp_connection_unique_ptr&& conn) {
  if (!conn) {
    return;
  }

  char* host;
  uint16_t port;
  evhttp_connection_get_peer(conn.get(), &host, &port);
  const HostPortPair key(host, port);

  lock_guard<mutex> lock(lock_);
  auto& entry(conns_[key]);

  entry.emplace_back(move(conn));
  while (entry.size() > FLAGS_url_fetcher_max_conn_per_host_port) {
    entry.pop_front();
  }
}


}  // namespace internal
}  // namespace cert_trans
