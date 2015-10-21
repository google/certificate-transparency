#include "server/handler_v2.h"

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
using cert_trans::HttpHandlerV2;
using cert_trans::JsonOutput;
using cert_trans::LoggedCertificate;
using cert_trans::Proxy;
using cert_trans::ScopedLatency;
using ct::ShortMerkleAuditProof;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;
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

HttpHandlerV2::HttpHandlerV2(JsonOutput* json_output,
              LogLookup<LoggedCertificate>* log_lookup,
              const ReadOnlyDatabase<LoggedCertificate>* db,
              const ClusterStateController<LoggedCertificate>* controller,
              const CertChecker* cert_checker, Frontend* frontend,
              Proxy* proxy, ThreadPool* pool, libevent::Base* event_base)
    : HttpHandler(json_output, log_lookup, db, controller, cert_checker,
                  frontend, proxy, pool, event_base) {};

HttpHandlerV2::~HttpHandlerV2() {}

void HttpHandlerV2::GetEntries(evhttp_request* req) const {
  output_->SendError(req, HTTP_NOTIMPLEMENTED, "Not yet implemented");
}


void HttpHandlerV2::GetRoots(evhttp_request* req) const {
  output_->SendError(req, HTTP_NOTIMPLEMENTED, "Not yet implemented");
}


void HttpHandlerV2::GetProof(evhttp_request* req) const {
  output_->SendError(req, HTTP_NOTIMPLEMENTED, "Not yet implemented");
}


void HttpHandlerV2::GetSTH(evhttp_request* req) const {
  output_->SendError(req, HTTP_NOTIMPLEMENTED, "Not yet implemented");
}


void HttpHandlerV2::GetConsistency(evhttp_request* req) const {
  output_->SendError(req, HTTP_NOTIMPLEMENTED, "Not yet implemented");
}


void HttpHandlerV2::AddChain(evhttp_request* req) {
  output_->SendError(req, HTTP_NOTIMPLEMENTED, "Not yet implemented");
}


void HttpHandlerV2::BlockingGetEntries(evhttp_request* req, int64_t start,
                                       int64_t end, bool include_scts) const {
  output_->SendError(req, HTTP_NOTIMPLEMENTED, "Not yet implemented");
}


void HttpHandlerV2::Add(libevent::HttpServer* server) {
  CHECK_NOTNULL(server);
  // TODO(pphaneuf): Find out which methods are CPU intensive enough
  // that they should be spun off to the thread pool.
  const string handler_path_prefix("/ct/v2/");

  AddProxyWrappedHandler(server, handler_path_prefix + "get-entries",
                         bind(&HttpHandlerV2::GetEntries, this, _1));
  // TODO(alcutter): Support this for mirrors too
  if (cert_checker_) {
    // Don't really need to proxy this one, but may as well just to keep
    // everything tidy:
    AddProxyWrappedHandler(server, handler_path_prefix + "get-roots",
                           bind(&HttpHandlerV2::GetRoots, this, _1));
  }
  AddProxyWrappedHandler(server, handler_path_prefix + "get-proof-by-hash",
                         bind(&HttpHandlerV2::GetProof, this, _1));
  AddProxyWrappedHandler(server, handler_path_prefix + "get-sth",
                         bind(&HttpHandlerV2::GetSTH, this, _1));
  AddProxyWrappedHandler(server, handler_path_prefix + "get-sth-consistency",
                         bind(&HttpHandlerV2::GetConsistency, this, _1));

  if (frontend_) {
    // Proxy the add-* calls too, technically we could serve them, but a
    // more up-to-date node will have a better chance of handling dupes
    // correctly, rather than bloating the tree.
    AddProxyWrappedHandler(server, handler_path_prefix + "add-chain",
                           bind(&HttpHandlerV2::AddChain, this, _1));
    AddProxyWrappedHandler(server, handler_path_prefix + "add-pre-chain",
                           bind(&HttpHandlerV2::AddPreChain, this, _1));
  }
}

void HttpHandlerV2::AddPreChain(evhttp_request* req) {
  output_->SendError(req, HTTP_NOTIMPLEMENTED, "Not yet implemented");
}


void HttpHandlerV2::BlockingAddChain(evhttp_request* req,
                                     const shared_ptr<CertChain>& chain) {
  output_->SendError(req, HTTP_NOTIMPLEMENTED, "Not yet implemented");
}


void HttpHandlerV2::BlockingAddPreChain(
    evhttp_request* req, const shared_ptr<PreCertChain>& chain) {
  output_->SendError(req, HTTP_NOTIMPLEMENTED, "Not yet implemented");
}

