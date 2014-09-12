#include "util/libevent_wrapper.h"

#include <event2/thread.h>
#include <glog/logging.h>
#include <math.h>

#include "base/time_support.h"

using boost::lock_guard;
using boost::mutex;
using boost::shared_ptr;
using std::string;
using std::vector;

namespace cert_trans {
namespace libevent {


struct HttpServer::Handler {
  Handler(const string &_path, const HandlerCallback &_cb)
      : path(_path),
        cb(_cb) {
  }

  const string path;
  const HandlerCallback cb;
};


Base::Base()
    : base_(event_base_new()) {
  evthread_make_base_notifiable(base_);
}


Base::~Base() {
  event_base_free(base_);
}


void Base::Add(const Event &ev, double timeout) {
  timeval tv;
  timeval *tvp(NULL);
  if (timeout >= 0) {
    tv.tv_sec = trunc(timeout);
    timeout -= tv.tv_sec;
    tv.tv_usec = timeout * kNumMicrosPerSecond;
    tvp = &tv;
  }
  CHECK_EQ(event_add(ev.ev_, tvp), 0);
}


void Base::Dispatch() {
  CHECK_EQ(event_base_dispatch(base_), 0);
}


Event::Event(const Base &base, evutil_socket_t sock, short events,
             const Callback &cb)
    : cb_(cb),
      ev_(event_new(base.get(), sock, events, &Dispatch, this)) {
}


Event::~Event() {
  event_free(ev_);
}


void Event::Dispatch(evutil_socket_t sock, short events, void *userdata) {
  static_cast<Event*>(userdata)->cb_(sock, events);
}


HttpServer::HttpServer(Base *base)
    : http_(CHECK_NOTNULL(evhttp_new(base->get()))) {
}


HttpServer::~HttpServer() {
  evhttp_free(http_);
  for (std::vector<Handler*>::iterator it = handlers_.begin();
       it != handlers_.end(); ++it) {
    delete *it;
  }
}


void HttpServer::Bind(const char *address, ev_uint16_t port) {
  CHECK_EQ(evhttp_bind_socket(http_, address, port), 0);
}


bool HttpServer::AddHandler(const string &path, const HandlerCallback &cb) {
  Handler *handler(new Handler(path, cb));
  handlers_.push_back(handler);

  return evhttp_set_cb(http_, path.c_str(), &HandleRequest, handler) == 0;
}


void HttpServer::HandleRequest(evhttp_request *req, void *userdata) {
  static_cast<Handler*>(userdata)->cb(req);
}


}  // namespace libevent
}  // namespace cert_trans
