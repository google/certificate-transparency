#ifndef CPP_SERVER_HANDLER_FACTORY_H_
#define CPP_SERVER_HANDLER_FACTORY_H_

#include "server/handler.h"

namespace cert_trans {

class HttpHandlerFactory {
  public:
   static HttpHandler* Create(
       JsonOutput* json_output, LogLookup<LoggedCertificate>* log_lookup,
       const ReadOnlyDatabase<LoggedCertificate>* db,
       const ClusterStateController<LoggedCertificate>* controller,
       const CertChecker* cert_checker, Frontend* frontend, Proxy* proxy,
       ThreadPool* pool, libevent::Base* event_base);
};
} // namespace cert_trans

#endif  // CPP_SERVER_HANDLER_FACTORY_V1_H_
