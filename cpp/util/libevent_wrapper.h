#ifndef CERT_TRANS_UTIL_LIBEVENT_WRAPPER_H_
#define CERT_TRANS_UTIL_LIBEVENT_WRAPPER_H_

#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <event2/event.h>
#include <event2/http.h>
#include <vector>

#include "base/macros.h"

namespace cert_trans {
namespace libevent {


class Event;


class Base {
 public:
  typedef boost::function<void(evutil_socket_t, short)> Callback;

  Base();
  ~Base();

  void Add(const Event &ev, double timeout);
  void Dispatch();

  event_base *get() const {
    return base_;
  }

 private:
  event_base *const base_;

  DISALLOW_COPY_AND_ASSIGN(Base);
};


class Event {
 public:
  typedef boost::function<void(evutil_socket_t, short)> Callback;

  Event(const Base &base, evutil_socket_t sock, short events,
        const Callback &cb);
  ~Event();

 private:
  friend class Base;

  static void Dispatch(evutil_socket_t sock, short events, void *userdata);

  const Callback cb_;
  event *const ev_;

  DISALLOW_COPY_AND_ASSIGN(Event);
};


class HttpServer {
 public:
  typedef boost::function<void(evhttp_request *)> HandlerCallback;

  explicit HttpServer(Base *base);
  ~HttpServer();

  void Bind(const char *address, ev_uint16_t port);

  // Returns false if there was an error adding the handler.
  bool AddHandler(const std::string &path, const HandlerCallback &cb);

 private:
  struct Handler;

  static void HandleRequest(evhttp_request *req, void *userdata);

  evhttp *const http_;
  // Could have been a vector<Handler>, but it is important that
  // pointers to entries remain valid.
  std::vector<Handler *> handlers_;

  DISALLOW_COPY_AND_ASSIGN(HttpServer);
};


}  // namespace libevent
}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_LIBEVENT_WRAPPER_H_
