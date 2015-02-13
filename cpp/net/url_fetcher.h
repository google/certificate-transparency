#ifndef CERT_TRANS_NET_URL_FETCHER_H_
#define CERT_TRANS_NET_URL_FETCHER_H_

#include <chrono>
#include <map>
#include <memory>
#include <string>

#include "base/macros.h"
#include "net/url.h"
#include "util/compare.h"
#include "util/task.h"

namespace cert_trans {

namespace libevent {
class Base;
}


class UrlFetcher {
 public:
  struct Request {
    Request(const URL& input_url) : url(input_url) {
    }

    URL url;
    std::string body;
  };

  struct Response {
    Response() : status_code(0) {
    }

    int status_code;
    std::multimap<std::string, std::string, ci_less<std::string>> headers;
    std::string body;
  };

  UrlFetcher(libevent::Base* base);
  virtual ~UrlFetcher();

  // With the following methods, if the status on the task is not OK,
  // the response will be in an undefined state. If it is OK, it only
  // means that the transaction with the remote server went correctly,
  // you should still check Response::status_code.
  virtual void Get(const Request& req, Response* resp, util::Task* task);
  virtual void Post(const Request& req, Response* resp, util::Task* task);

 protected:
  UrlFetcher();

 private:
  struct Impl;
  const std::unique_ptr<Impl> impl_;

  DISALLOW_COPY_AND_ASSIGN(UrlFetcher);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_NET_URL_FETCHER_H_
