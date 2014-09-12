#ifndef CERT_TRANS_SERVER_HANDLER_H_
#define CERT_TRANS_SERVER_HANDLER_H_

#include <string>

#include "server/ct_log_manager.h"
#include "util/libevent_wrapper.h"

namespace ct {
class CertChain;
class PreCertChain;
class SignedCertificateTimestamp;
}

namespace cert_trans {

class CTLogManager;
class ThreadPool;


class HttpHandler {
 public:
  HttpHandler(CTLogManager *manager, ThreadPool *pool);

  void Add(libevent::HttpServer *server);

 private:
  void GetEntries(evhttp_request *req) const;
  void GetRoots(evhttp_request *req) const;
  void GetProof(evhttp_request *req) const;
  void GetSTH(evhttp_request *req) const;
  void GetConsistency(evhttp_request *req) const;
  void AddChain(evhttp_request *req);
  void AddPreChain(evhttp_request *req);

  void BlockingAddChain(evhttp_request *req,
                        const boost::shared_ptr<ct::CertChain> &chain) const;
  void BlockingAddPreChain(
      evhttp_request *req,
      const boost::shared_ptr<ct::PreCertChain> &chain) const;

  CTLogManager *const manager_;
  ThreadPool *const pool_;

  DISALLOW_COPY_AND_ASSIGN(HttpHandler);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_SERVER_HANDLER_H_
