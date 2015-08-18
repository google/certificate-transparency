#include "server/handler_v1.h"

#include <functional>
#include <gflags/gflags.h>
#include <glog/logging.h>
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

using cert_trans::CertChain;
using cert_trans::CertChecker;
using cert_trans::HttpHandler;
using cert_trans::HttpHandlerV1;
using cert_trans::JsonOutput;
using cert_trans::LoggedCertificate;
using cert_trans::Proxy;
using cert_trans::ScopedLatency;
using ct::SignedCertificateTimestamp;
using std::bind;
using std::function;
using std::make_shared;
using std::multimap;
using std::mutex;
using std::placeholders::_1;
using std::shared_ptr;
using std::string;
using std::to_string;
using std::unique_ptr;
using std::vector;

HttpHandlerV1::HttpHandlerV1(JsonOutput* json_output,
              LogLookup<LoggedCertificate>* log_lookup,
              const ReadOnlyDatabase<LoggedCertificate>* db,
              const ClusterStateController<LoggedCertificate>* controller,
              const CertChecker* cert_checker, Frontend* frontend,
              Proxy* proxy, ThreadPool* pool, libevent::Base* event_base)
    : HttpHandler(json_output, log_lookup, db, controller, cert_checker,
                  frontend, proxy, pool, event_base) {};

HttpHandlerV1::~HttpHandlerV1() {}

void HttpHandlerV1::Add(libevent::HttpServer* server) {
  CHECK_NOTNULL(server);
  // TODO(pphaneuf): An optional prefix might be nice?
  // TODO(pphaneuf): Find out which methods are CPU intensive enough
  // that they should be spun off to the thread pool.
  string handler_path_prefix("/ct/v1/");

  AddProxyWrappedHandler(server, handler_path_prefix + "get-entries",
                         bind(&HttpHandler::GetEntries, this, _1));
  // TODO(alcutter): Support this for mirrors too
  if (cert_checker_) {
    // Don't really need to proxy this one, but may as well just to keep
    // everything tidy:
    AddProxyWrappedHandler(server, handler_path_prefix + "get-roots",
                           bind(&HttpHandler::GetRoots, this, _1));
  }
  AddProxyWrappedHandler(server, handler_path_prefix + "get-proof-by-hash",
                         bind(&HttpHandler::GetProof, this, _1));
  AddProxyWrappedHandler(server, handler_path_prefix + "get-sth",
                         bind(&HttpHandler::GetSTH, this, _1));
  AddProxyWrappedHandler(server, handler_path_prefix + "get-sth-consistency",
                         bind(&HttpHandler::GetConsistency, this, _1));

  if (frontend_) {
    // Proxy the add-* calls too, technically we could serve them, but a
    // more up-to-date node will have a better chance of handling dupes
    // correctly, rather than bloating the tree.
    AddProxyWrappedHandler(server, handler_path_prefix + "add-chain",
                           bind(&HttpHandler::AddChain, this, _1));
    AddProxyWrappedHandler(server, handler_path_prefix + "add-pre-chain",
                           bind(&HttpHandlerV1::AddPreChain, this, _1));
  }
}

void HttpHandlerV1::AddPreChain(evhttp_request* req) {
  const shared_ptr<PreCertChain> chain(make_shared<PreCertChain>());
  if (!ExtractChain(output_, req, chain.get())) {
    return;
  }

  pool_->Add(bind(&HttpHandlerV1::BlockingAddPreChain, this, req, chain));
}



void HttpHandlerV1::BlockingAddPreChain(
    evhttp_request* req, const shared_ptr<PreCertChain>& chain) {
  SignedCertificateTimestamp sct;

  AddChainReply(output_, req,
                CHECK_NOTNULL(frontend_)
                    ->QueuePreCertEntry(CHECK_NOTNULL(chain.get()), &sct),
                sct);
}

