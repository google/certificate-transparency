#ifndef CERT_TRANS_SERVER_HANDLER_H_
#define CERT_TRANS_SERVER_HANDLER_H_

#include <string>

#include "util/libevent_wrapper.h"

template<class T> class LogLookup;
class Frontend;

namespace ct {
class CertChain;
class CertChecker;
class LoggedCertificate;
class PreCertChain;
class SignedCertificateTimestamp;
}

namespace cert_trans {

class ThreadPool;


class HttpHandler {
 public:
  HttpHandler(LogLookup<ct::LoggedCertificate> *log_lookup,
              const ct::CertChecker *cert_checker, Frontend *frontend,
              ThreadPool *pool);

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

  LogLookup<ct::LoggedCertificate> *const log_lookup_;
  const ct::CertChecker *const cert_checker_;
  Frontend *const frontend_;
  ThreadPool *const pool_;

  DISALLOW_COPY_AND_ASSIGN(HttpHandler);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_SERVER_HANDLER_H_
