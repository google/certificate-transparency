#include "net/connection_pool.h"

#include <gflags/gflags.h>
#include <glog/logging.h>

using std::bind;
using std::lock_guard;
using std::move;
using std::mutex;
using std::pair;
using std::string;
using std::unique_lock;
using std::unique_ptr;

DEFINE_int32(url_fetcher_max_conn_per_host_port, 4,
             "maximum number of URL fetcher connections per host:port");

namespace cert_trans {
namespace internal {

ConnectionPool::Connection::Connection(evhtp_connection_t* conn,
                                       HostPortPair&& other_end)
    : conn_(CHECK_NOTNULL(conn)), other_end_(move(other_end)) {
}


const HostPortPair& ConnectionPool::Connection::other_end() const {
  return other_end_;
}


ConnectionPool::ConnectionPool(libevent::Base* base)
    : base_(CHECK_NOTNULL(base)), cleanup_scheduled_(false) {
}


// static
evhtp_res ConnectionPool::Connection::ConnectionClosedHook(
    evhtp_connection_t* conn, void* arg) {
  CHECK_NOTNULL(conn);
  CHECK_NOTNULL(arg);
  ConnectionPool::Connection* const c(
      static_cast<ConnectionPool::Connection*>(arg));
  VLOG(1) << "Releasing connection to " << c->other_end().first << ":"
          << c->other_end().second;
  CHECK_EQ(conn, c->connection());
  c->conn_.release();
  return EVHTP_RES_OK;
}


namespace {


void RemoveDeadConnectionsFromDeque(
    const unique_lock<mutex>& lock,
    std::deque<std::unique_ptr<ConnectionPool::Connection>>* deque) {
  CHECK(lock.owns_lock());
  CHECK(deque);

  // Do a sweep and remove any dead connections
  for (auto deque_it(deque->begin()); deque_it != deque->end();) {
    CHECK(*deque_it);
    if (!(*deque_it)->connection()) {
      VLOG(1) << "Removing dead connection to "
              << (*deque_it)->other_end().first << ":"
              << (*deque_it)->other_end().second;
      deque_it = deque->erase(deque_it);
      continue;
    }
    ++deque_it;
  }
}


}  // namespace


unique_ptr<ConnectionPool::Connection> ConnectionPool::Get(const URL& url) {
  // TODO(pphaneuf): Add support for other protocols.
  CHECK_EQ(url.Protocol(), "http");
  HostPortPair key(url.Host(), url.Port() != 0 ? url.Port() : 80);
  unique_lock<mutex> lock(lock_);

  auto it(conns_.find(key));

  if (it != conns_.end() && !it->second.empty()) {
    RemoveDeadConnectionsFromDeque(lock, &it->second);
  }

  if (it == conns_.end() || it->second.empty()) {
    VLOG(1) << "new evhtp_connection for " << key.first << ":" << key.second;
    unique_ptr<ConnectionPool::Connection> conn(
        new Connection(base_->HttpConnectionNew(key.first, key.second),
                       move(key)));
    evhtp_set_hook(&conn->connection()->hooks, evhtp_hook_on_connection_fini,
                   reinterpret_cast<evhtp_hook>(
                       Connection::ConnectionClosedHook),
                   reinterpret_cast<void*>(conn.get()));
    return conn;
  }

  VLOG(1) << "cached evhtp_connection for " << key.first << ":" << key.second;
  unique_ptr<ConnectionPool::Connection> retval(move(it->second.back()));
  it->second.pop_back();

  CHECK_NOTNULL(retval->connection());

  return retval;
}


void ConnectionPool::Put(unique_ptr<ConnectionPool::Connection>&& conn) {
  if (!conn) {
    VLOG(1) << "returned null Connection";
    return;
  }

  if (!conn->connection()) {
    VLOG(1) << "returned dead Connection";
    return;
  }

  const HostPortPair& key(conn->other_end());
  VLOG(1) << "returned Connection for " << key.first << ":" << key.second;
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
  unique_lock<mutex> lock(lock_);
  cleanup_scheduled_ = false;

  // std::map<HostPortPair, std::deque<unique_ptr<Connection>>> conns_;
  for (auto& entry : conns_) {
    RemoveDeadConnectionsFromDeque(lock, &entry.second);
    while (entry.second.size() >
           static_cast<uint>(FLAGS_url_fetcher_max_conn_per_host_port)) {
      entry.second.pop_front();
    }
  }
}


}  // namespace internal
}  // namespace cert_trans
