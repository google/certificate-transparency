#ifndef CERT_TRANS_UTIL_LIBEVENT_WRAPPER_H_
#define CERT_TRANS_UTIL_LIBEVENT_WRAPPER_H_

#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <boost/thread.hpp>
#include <event2/dns.h>
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

  void Dispatch();
  void DispatchOnce();
  void Break();

  event *EventNew(evutil_socket_t &sock, short events, Event *event) const;
  evhttp *HttpNew() const;
  evdns_base *GetDns();
  evhttp_connection *HttpConnectionNew(const std::string &host,
                                       unsigned short port);

 private:
  event_base *const base_;

  boost::mutex dns_lock_;
  evdns_base *dns_;

  DISALLOW_COPY_AND_ASSIGN(Base);
};


class Event {
 public:
  typedef boost::function<void(evutil_socket_t, short)> Callback;

  Event(const Base &base, evutil_socket_t sock, short events,
        const Callback &cb);
  ~Event();

  void Add(double timeout) const;
  // Note that this is only public so |Base| can use it.
  static void Dispatch(evutil_socket_t sock, short events, void *userdata);

 private:
  const Callback cb_;
  event *const ev_;

  DISALLOW_COPY_AND_ASSIGN(Event);
};


class HttpServer {
 public:
  typedef boost::function<void(evhttp_request *)> HandlerCallback;

  explicit HttpServer(const Base &base);
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


class HttpRequest {
 public:
  typedef boost::function<void(HttpRequest*)> Callback;

  explicit HttpRequest(const Callback &callback);
  ~HttpRequest();

  evhttp_request *get() {
    return req_;
  }

 private:
  static void Done(evhttp_request *req, void *userdata);

  const Callback callback_;
  evhttp_request *req_;

  DISALLOW_COPY_AND_ASSIGN(HttpRequest);
};


class HttpConnection {
 public:
  HttpConnection(const boost::shared_ptr<Base> &base, const evhttp_uri *uri);
  ~HttpConnection();

  // Takes ownership of "req", which will be automatically deleted
  // after its callback is called.
  void MakeRequest(HttpRequest *req, evhttp_cmd_type type,
                   const std::string &uri);

 private:
  evhttp_connection *const conn_;

  DISALLOW_COPY_AND_ASSIGN(HttpConnection);
};


}  // namespace libevent
}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_LIBEVENT_WRAPPER_H_
