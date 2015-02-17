#include "net/url_fetcher.h"

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include <glog/logging.h>

#include "net/connection_pool.h"

using cert_trans::internal::ConnectionPool;
using cert_trans::internal::evhttp_connection_unique_ptr;
using std::endl;
using std::make_pair;
using std::move;
using std::ostream;
using std::string;
using util::Status;
using util::Task;
using util::TaskHold;

namespace cert_trans {


struct UrlFetcher::Impl {
  Impl(libevent::Base* base) : pool_(CHECK_NOTNULL(base)) {
  }

  internal::ConnectionPool pool_;
};


namespace {


struct State {
  State(ConnectionPool* pool, evhttp_cmd_type verb,
        const UrlFetcher::Request& req, UrlFetcher::Response* resp,
        Task* task);

  ~State() {
    pool_->Put(move(conn_));
  }

  void RequestDone(evhttp_request* req);

  ConnectionPool* const pool_;
  evhttp_connection_unique_ptr conn_;
  const UrlFetcher::Request request_;
  UrlFetcher::Response* const response_;
  Task* const task_;

  evhttp_request* const http_req_;
};


void RequestCallback(evhttp_request* req, void* userdata) {
  static_cast<State*>(CHECK_NOTNULL(userdata))->RequestDone(req);
}


UrlFetcher::Request NormaliseRequest(UrlFetcher::Request req) {
  // Strip the body out to save space.
  req.body.clear();

  if (req.url.Path().empty()) {
    req.url.SetPath("/");
  }

  return req;
}


State::State(ConnectionPool* pool, evhttp_cmd_type verb,
             const UrlFetcher::Request& req, UrlFetcher::Response* resp,
             Task* task)
    : pool_(CHECK_NOTNULL(pool)),
      conn_(pool_->Get(req.url)),
      request_(NormaliseRequest(req)),
      response_(CHECK_NOTNULL(resp)),
      task_(CHECK_NOTNULL(task)),
      http_req_(CHECK_NOTNULL(evhttp_request_new(&RequestCallback, this))) {
  CHECK_NOTNULL(conn_.get());

  if (request_.url.Protocol() != "http") {
    VLOG(1) << "unsupported protocol: " << request_.url.Protocol();
    task->Return(
        Status(util::error::INVALID_ARGUMENT,
               "UrlFetcher: unsupported protocol: " + req.url.Protocol()));
    return;
  }

  evhttp_add_header(evhttp_request_get_output_headers(http_req_), "Host",
                    request_.url.Host().c_str());

  // Remember to use the parameter here, because the copy we keep in
  // request_ has the body stripped out to save space.
  if (!req.body.empty()) {
    if (evbuffer_add(evhttp_request_get_output_buffer(http_req_),
                     req.body.data(), req.body.size()) != 0) {
      VLOG(1) << "error when adding the request body";
      task->Return(
          Status(util::error::INTERNAL, "could not copy the request body"));
      return;
    }
  }

  VLOG(1) << "evhttp_make_request(" << conn_.get() << ", " << http_req_ << ", "
          << verb << ", \"" << request_.url.PathQuery() << "\")";
  if (evhttp_make_request(conn_.get(), http_req_, verb,
                          request_.url.PathQuery().c_str()) != 0) {
    VLOG(1) << "evhttp_make_request error";
    task->Return(Status(util::error::INTERNAL, "evhttp_make_request error"));
    return;
  }
}


void State::RequestDone(evhttp_request* req) {
  if (!req) {
    // TODO(pphaneuf): The dreaded null request... These are fairly
    // fatal things, like protocol parse errors, but could also be a
    // connection timeout. I think we should do retries in this case,
    // with a deadline of our own? At least, then, it would be easier
    // to distinguish between an obscure error, or a more common
    // timeout.
    VLOG(1) << "RequestCallback received a null request";
    task_->Return(Status::UNKNOWN);
    return;
  }

  response_->status_code = evhttp_request_get_response_code(req);
  if (response_->status_code < 100) {
    // TODO(pphaneuf): According to my reading of libevent, this is
    // most likely to be a connection refused?
    VLOG(1) << "request has a status code lower than 100: "
            << response_->status_code;
    task_->Return(
        Status(util::error::FAILED_PRECONDITION, "connection refused"));
    return;
  }

  for (evkeyval* ptr = evhttp_request_get_input_headers(req)->tqh_first; ptr;
       ptr = ptr->next.tqe_next) {
    response_->headers.insert(make_pair(ptr->key, ptr->value));
  }

  const size_t body_length(
      evbuffer_get_length(evhttp_request_get_input_buffer(req)));
  string body(reinterpret_cast<const char*>(evbuffer_pullup(
                  evhttp_request_get_input_buffer(req), body_length)),
              body_length);
  response_->body.swap(body);

  task_->Return();
}


}  // namespace


// Needs to be defined where Impl is also defined.
UrlFetcher::UrlFetcher() {
}


UrlFetcher::UrlFetcher(libevent::Base* base)
    : impl_(new Impl(CHECK_NOTNULL(base))) {
}


// Needs to be defined where Impl is also defined.
UrlFetcher::~UrlFetcher() {
}


void UrlFetcher::Get(const Request& req, Response* resp, Task* task) {
  TaskHold hold(task);

  State* const state(
      new State(&impl_->pool_, EVHTTP_REQ_GET, req, resp, task));
  task->DeleteWhenDone(state);
}


void UrlFetcher::Post(const Request& req, Response* resp, Task* task) {
  TaskHold hold(task);

  State* const state(
      new State(&impl_->pool_, EVHTTP_REQ_GET, req, resp, task));
  task->DeleteWhenDone(state);
}


ostream& operator<<(ostream& output, const UrlFetcher::Response& resp) {
  output << "status_code: " << resp.status_code << endl
         << "headers {" << endl;
  for (const auto& header : resp.headers) {
    output << "  " << header.first << ": " << header.second << endl;
  }
  output << "}" << endl
         << "body: <<EOF" << endl
         << resp.body << "EOF" << endl;

  return output;
}


}  // namespace cert_trans
