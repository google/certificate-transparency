#ifndef CERT_TRANS_NET_MOCK_URL_FETCHER_H_
#define CERT_TRANS_NET_MOCK_URL_FETCHER_H_

#include <gmock/gmock.h>

#include "net/url_fetcher.h"

namespace cert_trans {


class MockUrlFetcher : public UrlFetcher {
 public:
  MOCK_METHOD3(Get,
               void(const Request& req, Response* resp, util::Task* task));
  MOCK_METHOD3(Post,
               void(const Request& req, Response* resp, util::Task* task));
};


}  // namespace cert_trans

#endif  // CERT_TRANS_NET_MOCK_URL_FETCHER_H_
