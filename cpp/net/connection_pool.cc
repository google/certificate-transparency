#include "net/connection_pool.h"

#include <glog/logging.h>

using std::bind;
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
    : base_(CHECK_NOTNULL(base)), cleanup_scheduled_(false) {
}


evhttp_connection_unique_ptr ConnectionPool::Get(const URL& url) {
  // TODO(pphaneuf): Add support for other protocols.
  CHECK_EQ(url.Protocol(), "http");
  const HostPortPair key(url.Host(), url.Port() != 0 ? url.Port() : 80);
  lock_guard<mutex> lock(lock_);

  auto it(conns_.find(key));
  if (it == conns_.end() || it->second.empty()) {
    VLOG(1) << "new evhttp_connection for " << key.first << ":" << key.second;
    return evhttp_connection_unique_ptr(
        base_->HttpConnectionNew(key.first, key.second));
  }

  VLOG(1) << "cached evhttp_connection for " << key.first << ":" << key.second;
  evhttp_connection_unique_ptr retval(move(it->second.back()));
  it->second.pop_back();

  return retval;
}


void ConnectionPool::Put(evhttp_connection_unique_ptr&& conn) {
  if (!conn) {
    VLOG(1) << "returned null evhttp_connection";
    return;
  }

  char* host;
  uint16_t port;
  evhttp_connection_get_peer(conn.get(), &host, &port);
  const HostPortPair key(host, port);

  VLOG(1) << "returned evhttp_connection for " << key.first << ":"
          << key.second;
  lock_guard<mutex> lock(lock_);
  auto& entry(conns_[key]);

  CHECK_GE(FLAGS_url_fetcher_max_conn_per_host_port, 0);
  entry.emplace_back(move(conn));
  if (!cleanup_scheduled_ &&
      entry.size() >
          static_cast<uint>(FLAGS_url_fetcher_max_conn_per_host_port)) {
    cleanup_scheduled_ = true;
    base_->Add(bind(&ConnectionPool::Cleanup, this));
  }
}


void ConnectionPool::Cleanup() {
  lock_guard<mutex> lock(lock_);
  cleanup_scheduled_ = false;

  // std::map<HostPortPair, std::deque<evhttp_connection_unique_ptr>> conns_;
  for (auto& entry : conns_) {
    while (entry.second.size() >
           static_cast<uint>(FLAGS_url_fetcher_max_conn_per_host_port)) {
      entry.second.pop_front();
    }
  }

}


}  // namespace internal
}  // namespace cert_trans
