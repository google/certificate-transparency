#include "util/libevent_wrapper.h"

#include <event2/thread.h>
#include <glog/logging.h>
#include <math.h>

#include "base/time_support.h"

using std::lock_guard;
using std::mutex;
using std::shared_ptr;
using std::string;
using std::vector;

namespace {


unsigned short GetPortFromUri(const evhttp_uri* uri) {
  int retval(evhttp_uri_get_port(uri));

  if (retval < 1 || retval > 65535) {
    retval = 0;

    if (!strcmp("http", evhttp_uri_get_scheme(uri))) {
      retval = 80;
    }
  }

  return retval;
}


}  // namespace

namespace cert_trans {
namespace libevent {


struct HttpServer::Handler {
  Handler(const string& _path, const HandlerCallback& _cb)
      : path(_path), cb(_cb) {
  }

  const string path;
  const HandlerCallback cb;
};


Base::Base() : base_(event_base_new()), dns_(NULL) {
  evthread_make_base_notifiable(base_);
}


Base::~Base() {
  if (dns_)
    evdns_base_free(dns_, true);

  event_base_free(base_);
}


void Base::Dispatch() {
  // There should /never/ be more than 1 thread trying to call Dispatch(), so
  // we should expect to always own the lock here.
  CHECK(dispatch_lock_.try_lock());
  CHECK_EQ(event_base_dispatch(base_), 0);
  dispatch_lock_.unlock();
}


void Base::DispatchOnce() {
  // Only one thread can be running a dispatch loop at a time
  lock_guard<mutex> lock(dispatch_lock_);
  CHECK_EQ(event_base_loop(base_, EVLOOP_ONCE), 0);
}


event* Base::EventNew(evutil_socket_t& sock, short events,
                      Event* event) const {
  return CHECK_NOTNULL(
      event_new(base_, sock, events, &Event::Dispatch, event));
}


evhttp* Base::HttpNew() const {
  return CHECK_NOTNULL(evhttp_new(base_));
}


evdns_base* Base::GetDns() {
  lock_guard<mutex> lock(dns_lock_);

  if (!dns_) {
    dns_ = CHECK_NOTNULL(evdns_base_new(base_, 1));
  }

  return dns_;
}


evhttp_connection* Base::HttpConnectionNew(const string& host,
                                           unsigned short port) {
  return CHECK_NOTNULL(
      evhttp_connection_base_new(base_, GetDns(), host.c_str(), port));
}


Event::Event(const Base& base, evutil_socket_t sock, short events,
             const Callback& cb)
    : cb_(cb), ev_(base.EventNew(sock, events, this)) {
}


Event::~Event() {
  event_free(ev_);
}


void Event::Add(double timeout) const {
  timeval tv;
  timeval* tvp(NULL);

  if (timeout >= 0) {
    tv.tv_sec = trunc(timeout);
    timeout -= tv.tv_sec;
    tv.tv_usec = timeout * kNumMicrosPerSecond;
    tvp = &tv;
  }
  CHECK_EQ(event_add(ev_, tvp), 0);
}


void Event::Dispatch(evutil_socket_t sock, short events, void* userdata) {
  static_cast<Event*>(userdata)->cb_(sock, events);
}


HttpServer::HttpServer(const Base& base) : http_(base.HttpNew()) {
}


HttpServer::~HttpServer() {
  evhttp_free(http_);
  for (vector<Handler*>::iterator it = handlers_.begin();
       it != handlers_.end(); ++it) {
    delete *it;
  }
}


void HttpServer::Bind(const char* address, ev_uint16_t port) {
  CHECK_EQ(evhttp_bind_socket(http_, address, port), 0);
}


bool HttpServer::AddHandler(const string& path, const HandlerCallback& cb) {
  Handler* handler(new Handler(path, cb));
  handlers_.push_back(handler);

  return evhttp_set_cb(http_, path.c_str(), &HandleRequest, handler) == 0;
}


void HttpServer::HandleRequest(evhttp_request* req, void* userdata) {
  static_cast<Handler*>(userdata)->cb(req);
}


HttpRequest::HttpRequest(const Callback& callback)
    : callback_(callback),
      req_(CHECK_NOTNULL(evhttp_request_new(&HttpRequest::Done, this))),
      cancel_(nullptr),
      cancelled_(false) {
}


HttpRequest::~HttpRequest() {
  // If HttpRequest::Done or HttpRequest::Cancelled have been called,
  // req_ will have been freed by libevent itself.
  if (req_) {
    evhttp_request_free(req_);
  }

  // If the HttpRequest object is deleted and cancel_ isn't null, that
  // means that the self_ref_ has been nulled (so the request
  // completed), and so should mean that the cancel_ event is no
  // longer necessary. Calling event_free() also implies event_del(),
  // so if a call to HttpRequest::Cancelled is scheduled, it will, er,
  // be cancelled.
  if (cancel_) {
    event_free(cancel_);
  }
}


void HttpRequest::Cancel() {
  lock_guard<mutex> lock(cancel_lock_);
  CHECK(cancel_) << "tried to cancel an unstarted HttpRequest";
  CHECK(!cancelled_) << "tried to cancel an already cancelled HttpRequest";
  cancelled_ = true;
  event_active(cancel_, 0, 0);
}


void HttpRequest::Start(const shared_ptr<HttpRequest>& req,
                        evhttp_connection* conn, evhttp_cmd_type type,
                        const string& uri) {
  CHECK(req_) << "attempt to reuse an HttpRequest object";
  lock_guard<mutex> lock(cancel_lock_);
  CHECK(!cancelled_) << "starting an already cancelled request?!?";
  cancel_ = event_new(CHECK_NOTNULL(evhttp_connection_get_base(conn)), -1, 0,
                      &HttpRequest::Cancelled, this);

  CHECK_EQ(this, req.get());
  CHECK(!self_ref_);
  self_ref_ = req;
  CHECK_EQ(evhttp_make_request(conn, req_, type, uri.c_str()), 0);
}


// static
void HttpRequest::Done(evhttp_request* req, void* userdata) {
  // Keep ourselves alive at least for the remainder of this method.
  const shared_ptr<HttpRequest> self(
      static_cast<HttpRequest*>(CHECK_NOTNULL(userdata))->self_ref_);

  // We do CHECK_NOTNULL(userdata), but this is different, we're
  // checking that the self-reference has been set, and thus, that the
  // request has been started.
  CHECK(self);

  // The request is no longer running. The local reference will keep
  // it alive at least until this function returns.
  self->self_ref_.reset();


  // It would be very poor timing (and luck!), but it's possible that
  // another thread cancelled this request, in which case we should
  // not call the user callback (it might be pointing at freed
  // memory).
  //
  // If the request has not been cancelled, we'll still hold on to the
  // lock while the user callback runs, so HttpRequest::Cancel does
  // not return until it has completed.
  lock_guard<mutex> lock(self->cancel_lock_);
  if (!self->cancelled_) {
    // If we have a request, it should be non-NULL. But sometimes we
    // don't have one...
    if (req) {
      CHECK_EQ(self->req_, req);
      self->callback_(self);
    } else {
      self->callback_(nullptr);
    }
  }

  // Once we return from this function, libevent will free "req_" for
  // us.
  self->req_ = NULL;
}


// static
void HttpRequest::Cancelled(evutil_socket_t sock, short flag, void* userdata) {
  HttpRequest* self(static_cast<HttpRequest*>(CHECK_NOTNULL(userdata)));

  // The callback has already run, it is too late to cancel.
  if (!self->req_) {
    return;
  }

  // Keep ourselves alive at least for the remainder of this method.
  const shared_ptr<HttpRequest> ref(self->self_ref_);

  // Check that the request has been started, and that our reference
  // is valid.
  CHECK(ref);

  evhttp_cancel_request(self->req_);
  self->req_ = nullptr;
  self->self_ref_.reset();
}


HttpConnection::HttpConnection(const shared_ptr<Base>& base,
                               const evhttp_uri* uri)
    : base_(base),
      conn_(base->HttpConnectionNew(evhttp_uri_get_host(CHECK_NOTNULL(uri)),
                                    GetPortFromUri(uri))) {
}


HttpConnection::HttpConnection(const shared_ptr<Base>& base,
                               const string& host, unsigned short port)
    : base_(base), conn_(CHECK_NOTNULL(base->HttpConnectionNew(host, port))) {
}


HttpConnection::~HttpConnection() {
  evhttp_connection_free(conn_);
}


HttpConnection* HttpConnection::Clone() const {
  char* host(nullptr);
  ev_uint16_t port(0);

  evhttp_connection_get_peer(conn_, &host, &port);
  CHECK_NOTNULL(host);
  CHECK_GT(port, 0);

  return new HttpConnection(base_, host, port);
}


void HttpConnection::MakeRequest(const shared_ptr<HttpRequest>& req,
                                 evhttp_cmd_type type, const string& uri) {
  req->Start(req, conn_, type, uri);
}


void HttpConnection::SetTimeout(int timeout_secs) {
  evhttp_connection_set_timeout(conn_, timeout_secs);
}


}  // namespace libevent
}  // namespace cert_trans
