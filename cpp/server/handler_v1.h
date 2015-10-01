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

  virtual void GetEntries(evhttp_request* req) const override;
  virtual void GetRoots(evhttp_request* req) const override;
  virtual void GetProof(evhttp_request* req) const override;
  virtual void GetSTH(evhttp_request* req) const override;
  virtual void GetConsistency(evhttp_request* req) const override;
  virtual void AddChain(evhttp_request* req) override;
  virtual void Add(libevent::HttpServer* server) override;
  virtual void AddPreChain(evhttp_request* req) override;
  virtual void BlockingGetEntries(evhttp_request* req, int64_t start,
                                  int64_t end,
                                  bool include_scts) const override;
  virtual void BlockingAddChain(
      evhttp_request* req, const std::shared_ptr<CertChain>& chain) override;
  virtual void BlockingAddPreChain(
      evhttp_request* req,
      const std::shared_ptr<PreCertChain>& chain) override;

  DISALLOW_COPY_AND_ASSIGN(HttpHandlerV1);
};
}  // namespace cert_trans

#endif  // CERT_TRANS_SERVER_HANDLER_V1_H_
