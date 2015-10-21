#include <functional>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <server/handler_factory.h>
#include <server/handler_v1.h>
#include <map>
#include <memory>
#include <stdlib.h>

#include "log/cert.h"
#include "log/cert_checker.h"
#include "log/cluster_state_controller.h"
#include "log/frontend.h"
#include "log/log_lookup.h"
#include "log/logged_certificate.h"
#include "monitoring/monitoring.h"
#include "monitoring/latency.h"
#include "server/json_output.h"
#include "server/proxy.h"
#include "util/json_wrapper.h"
#include "util/thread_pool.h"

using cert_trans::JsonOutput;
using cert_trans::HttpHandler;
using cert_trans::HttpHandlerFactory;
using cert_trans::HttpHandlerV1;
using cert_trans::LoggedCertificate;

HttpHandler* HttpHandlerFactory::Create(
    JsonOutput* json_output, LogLookup<LoggedCertificate>* log_lookup,
    const ReadOnlyDatabase<LoggedCertificate>* db,
    const ClusterStateController<LoggedCertificate>* controller,
    const CertChecker* cert_checker, Frontend* frontend, Proxy* proxy,
    ThreadPool* pool, libevent::Base* event_base) {
  return new HttpHandlerV1(json_output, log_lookup, db, controller,
                           cert_checker, frontend, proxy, pool, event_base);

}
