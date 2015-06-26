#include "net/connection_pool.h"

#include <chrono>
#include <gflags/gflags.h>
#include <glog/logging.h>

#include "monitoring/monitoring.h"
#include "util/openssl_util.h"

extern "C" {
#include "third_party/curl/hostcheck.h"
#include "third_party/isec_partners/openssl_hostname_validation.h"
}  // extern "C"


using std::bind;
using std::chrono::duration_cast;
using std::chrono::seconds;
using std::chrono::system_clock;
using std::lock_guard;
using std::make_pair;
using std::map;
using std::move;
using std::mutex;
using std::pair;
using std::placeholders::_1;
using std::placeholders::_2;
using std::string;
using std::to_string;
using std::unique_lock;
using std::unique_ptr;
using util::ClearOpenSSLErrors;
using util::DumpOpenSSLErrorStack;

DEFINE_int32(
    connection_read_timeout_seconds, 60,
    "Connection read timeout in seconds, only applies while willing to read.");
DEFINE_int32(connection_write_timeout_seconds, 60,
             "Connection write timeout in seconds, only applies while willing "
             "to write.");
DEFINE_int32(
    connection_pool_max_unused_age_seconds, 60 * 5,
    "When there are more than --url_fetcher_max_conn_per_host_port "
    "connections per host:port pair, any unused for at least this long will "
    "be removed.");
DEFINE_string(trusted_root_certs, "/etc/ssl/certs/ca-certificates.crt",
              "Location of trusted CA root certs for outgoing SSL "
              "connections.");
DEFINE_int32(url_fetcher_max_conn_per_host_port, 4,
             "maximum number of URL fetcher connections per host:port");


namespace cert_trans {
namespace internal {


const int kZeroMillis = 0;


static Gauge<string>* connections_per_host_port(
    Gauge<string>::New("connections_per_host_port", "host_port",
                       "Number of cached connections port host:port"));


string HostPortString(const HostPortPair& pair) {
  return pair.first + ":" + to_string(pair.second);
}


// static
int ConnectionPool::Connection::SSLVerifyCallback(const int preverify_ok,
                                                  X509_STORE_CTX* x509_ctx) {
  CHECK_NOTNULL(x509_ctx);
  X509* const server_cert(
      CHECK_NOTNULL(X509_STORE_CTX_get_current_cert(x509_ctx)));

  if (preverify_ok == 0) {
    const int err(X509_STORE_CTX_get_error(x509_ctx));
    char buf[256];
    X509_NAME_oneline(X509_get_subject_name(server_cert), buf, 256);

    LOG(WARNING) << "OpenSSL failed to verify cert for " << buf << ": "
                 << X509_verify_cert_error_string(err);
    return preverify_ok;
  }

  // Only do extra checks (i.e. hostname matching) for the end-entity cert.
  const int depth(X509_STORE_CTX_get_error_depth(x509_ctx));
  if (depth > 0) {
    return preverify_ok;
  }

  const SSL* const ssl(static_cast<SSL*>(CHECK_NOTNULL(
      X509_STORE_CTX_get_ex_data(x509_ctx,
                                 SSL_get_ex_data_X509_STORE_CTX_idx()))));
  const ConnectionPool::Connection* const conn(
      CHECK_NOTNULL(static_cast<const ConnectionPool::Connection*>(
          SSL_get_ex_data(ssl, GetSSLConnectionIndex()))));

  const HostnameValidationResult hostname_valid(
      validate_hostname(conn->other_end().first.c_str(), server_cert));
  if (hostname_valid != MatchFound) {
    string error;
    switch (hostname_valid) {
      case MatchFound:
        LOG(FATAL) << "Shouldn't get here.";
        break;
      case MatchNotFound:
        error = "certificate doesn't match hostname";
        break;
      case NoSANPresent:
        // I don't think we should ever see this, should be handled inside
        // validate_hostname()
        error = "no SAN present";
        break;
      case MalformedCertificate:
        error = "certificate is malformed";
        break;
      case Error:
        error = "unknown error";
        break;
    }
    if (conn->connection()->request) {
      conn->connection()->request->status = kSSLErrorStatus;
    }
    LOG_EVERY_N(WARNING, 100)
        << "Failed to validate SSL certificate: " << error << " : "
        << DumpOpenSSLErrorStack();
    ClearOpenSSLErrors();
    return 0;
  }
  return 1;
}


// static
int ConnectionPool::Connection::GetSSLConnectionIndex() {
  static const int ssl_connection_index(
      SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr));
  return ssl_connection_index;
}


ConnectionPool::Connection::Connection(evhtp_connection_t* conn,
                                       HostPortPair&& other_end)
    : conn_(CHECK_NOTNULL(conn)), other_end_(move(other_end)) {
  if (conn_->ssl) {
    SSL_set_ex_data(conn_->ssl, GetSSLConnectionIndex(),
                    static_cast<void*>(this));
    SSL_set_tlsext_host_name(conn_->ssl, other_end_.first.c_str());
  }
}


const HostPortPair& ConnectionPool::Connection::other_end() const {
  return other_end_;
}


void ConnectionPool::Connection::ReleaseConnection() {
  conn_.release();
  // Do not null out ssl_, despite the fact that it's a dangling pointer now we
  // need it in the d'tor since the value of the pointer itself is a key into a
  // map which needs to be updated.
}


ConnectionPool::ConnectionPool(libevent::Base* base)
    : base_(CHECK_NOTNULL(base)),
      cleanup_scheduled_(false),
      ssl_ctx_(SSL_CTX_new(TLSv1_client_method()), SSL_CTX_free) {
  CHECK(ssl_ctx_) << "could not build SSL context: " << DumpOpenSSLErrorStack();

  // Try to load trusted root certificates.
  // TODO(alcutter): This is probably Linux specific, we'll need other sections
  // for OSX etc.
  if (SSL_CTX_load_verify_locations(ssl_ctx_.get(),
                                    FLAGS_trusted_root_certs.c_str(),
                                    nullptr) != 1) {
    DumpOpenSSLErrorStack();
    LOG(FATAL) << "Couldn't load trusted root certificates.";
  }

  SSL_CTX_set_verify(ssl_ctx_.get(), SSL_VERIFY_PEER,
                     Connection::SSLVerifyCallback);
}


// static
evhtp_res ConnectionPool::Connection::ConnectionErrorHook(
    evhtp_connection_t* conn, evhtp_error_flags errtype, void* arg) {
  CHECK_NOTNULL(conn);
  CHECK_NOTNULL(arg);
  CHECK(libevent::Base::OnEventThread());
  ConnectionPool::Connection* const c(
      static_cast<ConnectionPool::Connection*>(arg));
  VLOG(1) << "Releasing errored connection to " << c->other_end().first << ":"
          << c->other_end().second;

  CHECK_EQ(conn, c->connection());

  // Need to let the client know their request has failed, seems evhtp doesn't
  // do that by default so we'll call the request done callback here.
  if (conn->request) {
    // If someone hasn't already modified the default status, set it to a
    // generic "something went wrong" value here:
    if (conn->request->status == 200) {
      conn->request->status = kUnknownErrorStatus;
    }
    conn->request->cb(conn->request, conn->request->cbarg);
    conn->request = nullptr;
  }

  c->ReleaseConnection();
  return EVHTP_RES_OK;
}


// static
void ConnectionPool::RemoveDeadConnectionsFromDeque(
    const unique_lock<mutex>& lock,
    std::deque<ConnectionPool::TimestampedConnection>* deque) {
  CHECK(lock.owns_lock());
  CHECK(deque);

  // Do a sweep and remove any dead connections
  for (auto deque_it(deque->begin()); deque_it != deque->end();) {
    CHECK(deque_it->second);
    if (!deque_it->second->connection()) {
      VLOG(1) << "Removing dead connection to "
              << deque_it->second->other_end().first << ":"
              << deque_it->second->other_end().second;
      deque_it = deque->erase(deque_it);
      continue;
    }
    ++deque_it;
  }
}


unique_ptr<ConnectionPool::Connection> ConnectionPool::Get(const URL& url) {
  CHECK(url.Protocol() == "http" || url.Protocol() == "https");
  const uint16_t default_port(url.Protocol() == "https" ? 443 : 80);
  HostPortPair key(url.Host(), url.Port() != 0 ? url.Port() : default_port);
  unique_lock<mutex> lock(lock_);

  auto it(conns_.find(key));

  if (it != conns_.end() && !it->second.empty()) {
    RemoveDeadConnectionsFromDeque(lock, &it->second);
  }

  if (it == conns_.end() || it->second.empty()) {
    VLOG(1) << "new evhtp_connection for " << key.first << ":" << key.second;
    unique_ptr<ConnectionPool::Connection> conn(new Connection(
        url.Protocol() == "https"
            ? base_->HttpsConnectionNew(key.first, key.second, ssl_ctx_.get())
            : base_->HttpConnectionNew(key.first, key.second),
        move(key)));
    struct timeval read_timeout = {FLAGS_connection_read_timeout_seconds,
                                   kZeroMillis};
    struct timeval write_timeout = {FLAGS_connection_write_timeout_seconds,
                                    kZeroMillis};
    evhtp_connection_set_timeouts(conn->connection(), &read_timeout,
                                  &write_timeout);
    evhtp_set_hook(&conn->connection()->hooks, evhtp_hook_on_conn_error,
                   reinterpret_cast<evhtp_hook>(
                       Connection::ConnectionErrorHook),
                   reinterpret_cast<void*>(conn.get()));
    return conn;
  }

  VLOG(1) << "cached evhtp_connection for " << key.first << ":" << key.second;
  unique_ptr<ConnectionPool::Connection> retval(
      move(it->second.back().second));
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
  entry.emplace_back(make_pair(system_clock::now(), move(conn)));
  const string hostport(HostPortString(key));
  VLOG(1) << "ConnectionPool for " << hostport << " size : " << entry.size();
  connections_per_host_port->Set(hostport, entry.size());
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
  const system_clock::time_point cutoff(
      system_clock::now() -
      seconds(FLAGS_connection_pool_max_unused_age_seconds));

  // conns_ is a std::map<HostPortPair, std::deque<TimestampedConnection>>
  for (auto& entry : conns_) {
    RemoveDeadConnectionsFromDeque(lock, &entry.second);
    while (entry.second.front().first < cutoff &&
           entry.second.size() >
               static_cast<uint>(FLAGS_url_fetcher_max_conn_per_host_port)) {
      entry.second.pop_front();
    }
    const string hostport(HostPortString(entry.first));
    VLOG(1) << "ConnectionPool for " << hostport
            << " size : " << entry.second.size();
    connections_per_host_port->Set(hostport, entry.second.size());
  }
}


}  // namespace internal
}  // namespace cert_trans
