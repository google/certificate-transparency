#ifndef CERT_TRANS_UTIL_LIBEVENT_WRAPPER_H_
#define CERT_TRANS_UTIL_LIBEVENT_WRAPPER_H_

#include <chrono>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/http.h>
#include <memory>
#include <mutex>
#include <vector>

#include "base/macros.h"
#include "util/executor.h"

namespace cert_trans {
namespace libevent {


class Event;
class HttpConnection;


class Base : public util::Executor {
 public:
  Base();
  ~Base();

  // Arranges to run the closure on the main loop.
  void Add(const std::function<void()>& cb) override;

  void Dispatch();
  void DispatchOnce();

  event* EventNew(evutil_socket_t& sock, short events, Event* event) const;
  evhttp* HttpNew() const;
  evdns_base* GetDns();
  evhttp_connection* HttpConnectionNew(const std::string& host,
                                       unsigned short port);

 private:
  static void RunClosures(evutil_socket_t sock, short flag, void* userdata);

  event_base* const base_;
  std::mutex dispatch_lock_;

  std::mutex dns_lock_;
  evdns_base* dns_;

  std::mutex closures_lock_;
  const std::unique_ptr<event, void (*)(event*)> wake_closures_;
  std::vector<std::function<void()>> closures_;

  DISALLOW_COPY_AND_ASSIGN(Base);
};


class Event {
 public:
  typedef std::function<void(evutil_socket_t, short)> Callback;

  Event(const Base& base, evutil_socket_t sock, short events,
        const Callback& cb);
  ~Event();

  void Add(const std::chrono::duration<double>& timeout) const;
  // Note that this is only public so |Base| can use it.
  static void Dispatch(evutil_socket_t sock, short events, void* userdata);

 private:
  const Callback cb_;
  event* const ev_;

  DISALLOW_COPY_AND_ASSIGN(Event);
};


class HttpServer {
 public:
  typedef std::function<void(evhttp_request*)> HandlerCallback;

  explicit HttpServer(const Base& base);
  ~HttpServer();

  void Bind(const char* address, ev_uint16_t port);

  // Returns false if there was an error adding the handler.
  bool AddHandler(const std::string& path, const HandlerCallback& cb);

 private:
  struct Handler;

  static void HandleRequest(evhttp_request* req, void* userdata);

  evhttp* const http_;
  // Could have been a vector<Handler>, but it is important that
  // pointers to entries remain valid.
  std::vector<Handler*> handlers_;

  DISALLOW_COPY_AND_ASSIGN(HttpServer);
};


class HttpRequest : public std::enable_shared_from_this<HttpRequest> {
 public:
  typedef std::function<void(const std::shared_ptr<HttpRequest>&)> Callback;

  // Once this callback returns, the object becomes invalid.
  explicit HttpRequest(const Callback& callback);
  ~HttpRequest();

  // After calling this, the object becomes invalid, and any reference
  // to it should be disposed of. If it is too late to cancel and the
  // callback is still running, this method will block until the
  // callback has returned.
  void Cancel();

  int GetResponseCode() const {
    return evhttp_request_get_response_code(req_);
  }
  evkeyvalq* GetInputHeaders() const {
    return evhttp_request_get_input_headers(req_);
  }
  evbuffer* GetInputBuffer() const {
    return evhttp_request_get_input_buffer(req_);
  }
  evkeyvalq* GetOutputHeaders() const {
    return evhttp_request_get_output_headers(req_);
  }
  evbuffer* GetOutputBuffer() const {
    return evhttp_request_get_output_buffer(req_);
  }

 private:
  friend class HttpConnection;

  // Called by HttpConnection.
  void Start(const std::shared_ptr<HttpConnection>& conn, evhttp_cmd_type type,
             const std::string& uri);

  static void Done(evhttp_request* req, void* userdata);
  static void Cancelled(evutil_socket_t sock, short flag, void* userdata);

  const Callback callback_;

  evhttp_request* req_;
  // We keep a reference to the HttpConnection as long as this request
  // is outstanding, to make sure it doesn't disappear from under us.
  std::shared_ptr<HttpConnection> conn_;

  // A self-reference to keep the request object alive, as long as
  // it's running.
  std::shared_ptr<HttpRequest> self_ref_;

  std::mutex cancel_lock_;
  event* cancel_;
  bool cancelled_;

  DISALLOW_COPY_AND_ASSIGN(HttpRequest);
};


class HttpConnection : public std::enable_shared_from_this<HttpConnection> {
 public:
  HttpConnection(const std::shared_ptr<Base>& base, const evhttp_uri* uri);
  ~HttpConnection();

  // This method does not simply clone the object, but creates a
  // separate socket altogether. This can be useful for "hanging
  // GETs", for example, which would otherwise prevent other requests
  // from being made on the connection.
  std::shared_ptr<HttpConnection> Clone() const;

  // Once you pass an HttpRequest to this method, you shouldn't call
  // any of its methods (except for HttpRequest::Cancel), until the
  // callback is called.
  void MakeRequest(const std::shared_ptr<HttpRequest>& req,
                   evhttp_cmd_type type, const std::string& uri);

  void SetTimeout(const std::chrono::seconds& timeout);

 private:
  friend class HttpRequest;

  HttpConnection(const std::shared_ptr<Base>& base, const std::string& host,
                 unsigned short port);

  const std::shared_ptr<Base> base_;
  evhttp_connection* const conn_;

  DISALLOW_COPY_AND_ASSIGN(HttpConnection);
};


}  // namespace libevent
}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_LIBEVENT_WRAPPER_H_
