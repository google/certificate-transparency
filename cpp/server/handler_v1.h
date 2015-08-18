#ifndef CERT_TRANS_SERVER_HANDLER_V1_H_
#define CERT_TRANS_SERVER_HANDLER_V1_H_

#include "server/handler.h"

namespace cert_trans {

class HttpHandlerV1 : public HttpHandler {
 public:
  HttpHandlerV1(JsonOutput* json_output,
                LogLookup<LoggedCertificate>* log_lookup,
                const ReadOnlyDatabase<LoggedCertificate>* db,
                const ClusterStateController<LoggedCertificate>* controller,
                const CertChecker* cert_checker, Frontend* frontend,
                Proxy* proxy, ThreadPool* pool, libevent::Base* event_base);

  ~HttpHandlerV1();

  void Add(libevent::HttpServer* server) override;

  void AddPreChain(evhttp_request* req) override;

  void BlockingAddPreChain(
      evhttp_request* req,
      const std::shared_ptr<PreCertChain>& chain) override;

  DISALLOW_COPY_AND_ASSIGN(HttpHandlerV1);
};
}  // namespace cert_trans

#endif  // CERT_TRANS_SERVER_HANDLER_V1_H_
