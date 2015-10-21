#include "server/handler.h"

#include <algorithm>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <functional>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <map>
#include <memory>
#include <stdlib.h>
#include <utility>
#include <vector>

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

namespace libevent = cert_trans::libevent;

using cert_trans::Cert;
using cert_trans::CertChain;
using cert_trans::CertChecker;
using cert_trans::Counter;
using cert_trans::HttpHandler;
using cert_trans::JsonOutput;
using cert_trans::Latency;
using cert_trans::LoggedCertificate;
using cert_trans::Proxy;
using cert_trans::ScopedLatency;
using ct::ShortMerkleAuditProof;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;
using std::bind;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::function;
using std::lock_guard;
using std::make_pair;
using std::make_shared;
using std::multimap;
using std::mutex;
using std::placeholders::_1;
using std::shared_ptr;
using std::string;
using std::to_string;
using std::unique_ptr;
using std::vector;

DEFINE_int32(max_leaf_entries_per_response, 1000,
             "maximum number of entries to put in the response of a "
             "get-entries request");
DEFINE_int32(staleness_check_delay_secs, 5,
             "number of seconds between node staleness checks");

namespace {


static Latency<milliseconds, string> http_server_request_latency_ms(
    "total_http_server_request_latency_ms", "path",
    "Total request latency in ms broken down by path");


}  // namespace


HttpHandler::HttpHandler(
    JsonOutput* output, LogLookup<LoggedCertificate>* log_lookup,
    const ReadOnlyDatabase<LoggedCertificate>* db,
    const ClusterStateController<LoggedCertificate>* controller,
    const CertChecker* cert_checker, Frontend* frontend, Proxy* proxy,
    ThreadPool* pool, libevent::Base* event_base)
    : output_(CHECK_NOTNULL(output)),
      log_lookup_(CHECK_NOTNULL(log_lookup)),
      db_(CHECK_NOTNULL(db)),
      controller_(CHECK_NOTNULL(controller)),
      cert_checker_(cert_checker),
      frontend_(frontend),
      proxy_(CHECK_NOTNULL(proxy)),
      pool_(CHECK_NOTNULL(pool)),
      event_base_(CHECK_NOTNULL(event_base)),
      task_(pool_),
      node_is_stale_(controller_->NodeIsStale()) {
  event_base_->Delay(seconds(FLAGS_staleness_check_delay_secs),
                     task_.task()->AddChild(
                         bind(&HttpHandler::UpdateNodeStaleness, this)));
}


HttpHandler::~HttpHandler() {
  task_.task()->Return();
  task_.Wait();
}

int HttpHandler::GetMaxLeafEntriesPerResponse() const {
  return FLAGS_max_leaf_entries_per_response;
}

multimap<string, string> HttpHandler::ParseQuery(evhttp_request* req) const {
  evkeyvalq keyval;
  multimap<string, string> retval;

  // We return an empty result in case of a parsing error.
  if (evhttp_parse_query_str(evhttp_uri_get_query(
                                 evhttp_request_get_evhttp_uri(req)),
                             &keyval) == 0) {
    for (evkeyval* i = keyval.tqh_first; i; i = i->next.tqe_next) {
      retval.insert(make_pair(i->key, i->value));
    }
  }

  return retval;
}

bool HttpHandler::GetParam(const multimap<string, string>& query,
                           const string& param, string* value) const {
  CHECK_NOTNULL(value);

  multimap<string, string>::const_iterator it = query.find(param);
  if (it == query.end()) {
    return false;
  }

  const string possible_value(it->second);
  ++it;

  // Flag duplicate query parameters as invalid.
  const bool retval(it == query.end() || it->first != param);
  if (retval) {
    *value = possible_value;
  }

  return retval;
}


// Returns -1 on error, and on success too if the parameter contains
// -1 (so it's advised to only use it when expecting unsigned
// parameters).
int64_t HttpHandler::GetIntParam(const multimap<string, string>& query,
                                 const string& param) const {
  int retval(-1);
  string value;
  if (GetParam(query, param, &value)) {
    errno = 0;
    const long num(strtol(value.c_str(), /*endptr*/ NULL, 10));
    // Detect strtol() errors or overflow/underflow when casting to
    // retval's type clips the value. We do the following by doing it,
    // and checking that they're still equal afterward (this will
    // still work if we change retval's type later on).
    retval = num;
    if (errno || static_cast<long>(retval) != num) {
      VLOG(1) << "over/underflow getting \"" << param << "\": " << retval
              << ", " << num << " (" << strerror(errno) << ")";
      retval = -1;
    }
  }

  return retval;
}

bool HttpHandler::GetBoolParam(const multimap<string, string>& query,
                               const string& param) const {
  string value;
  if (GetParam(query, param, &value)) {
    return (value == "true");
  } else {
    return false;
  }
}

void StatsHandlerInterceptor(const string& path,
                             const libevent::HttpServer::HandlerCallback& cb,
                             evhttp_request* req) {
  ScopedLatency total_http_server_request_latency(
      http_server_request_latency_ms.GetScopedLatency(path));

  cb(req);
}


void HttpHandler::ProxyInterceptor(
    const libevent::HttpServer::HandlerCallback& local_handler,
    evhttp_request* request) {
  VLOG(2) << "Running proxy interceptor...";
  // TODO(alcutter): We can be a bit smarter about when to proxy off
  // the request - being stale wrt to the current serving STH doesn't
  // automatically mean we're unable to answer this request.
  if (IsNodeStale()) {
    // Can't do this on the libevent thread since it can block on the lock in
    // ClusterStatusController::GetFreshNodes().
    pool_->Add(bind(&Proxy::ProxyRequest, proxy_, request));
  } else {
    local_handler(request);
  }
}


void HttpHandler::AddProxyWrappedHandler(
    libevent::HttpServer* server, const string& path,
    const libevent::HttpServer::HandlerCallback& local_handler) {
  const libevent::HttpServer::HandlerCallback stats_handler(
      bind(&StatsHandlerInterceptor, path, local_handler, _1));
  CHECK(server->AddHandler(path, bind(&HttpHandler::ProxyInterceptor, this,
                                      stats_handler, _1)));
}

bool HttpHandler::ExtractChain(JsonOutput* output, evhttp_request* req,
                               CertChain* chain) {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
    output->SendError(req, HTTP_BADMETHOD, "Method not allowed.");
    return false;
  }

  // TODO(pphaneuf): Should we check that Content-Type says
  // "application/json", as recommended by RFC4627?
  JsonObject json_body(evhttp_request_get_input_buffer(req));
  if (!json_body.Ok() || !json_body.IsType(json_type_object)) {
    output->SendError(req, HTTP_BADREQUEST, "Unable to parse provided JSON.");
    return false;
  }

  JsonArray json_chain(json_body, "chain");
  if (!json_chain.Ok()) {
    output->SendError(req, HTTP_BADREQUEST, "Unable to parse provided JSON.");
    return false;
  }

  VLOG(2) << "ExtractChain chain:\n" << json_chain.DebugString();

  for (int i = 0; i < json_chain.Length(); ++i) {
    JsonString json_cert(json_chain, i);
    if (!json_cert.Ok()) {
      output->SendError(req, HTTP_BADREQUEST,
                        "Unable to parse provided JSON.");
      return false;
    }

    unique_ptr<Cert> cert(new Cert);
    cert->LoadFromDerString(json_cert.FromBase64());
    if (!cert->IsLoaded()) {
      output->SendError(req, HTTP_BADREQUEST,
                        "Unable to parse provided chain.");
      return false;
    }

    chain->AddCert(cert.release());
  }

  return true;
}

void HttpHandler::AddChainReply(JsonOutput* output, evhttp_request* req,
                                const util::Status& add_status,
                                const SignedCertificateTimestamp& sct) {
  if (!add_status.ok() &&
      add_status.CanonicalCode() != util::error::ALREADY_EXISTS) {
    VLOG(1) << "error adding chain: " << add_status;
    const int response_code(add_status.CanonicalCode() ==
                                    util::error::RESOURCE_EXHAUSTED
                                ? HTTP_SERVUNAVAIL
                                : HTTP_BADREQUEST);
    return output->SendError(req, response_code, add_status.error_message());
  }

  JsonObject json_reply;
  json_reply.Add("sct_version", static_cast<int64_t>(0));
  json_reply.AddBase64("id", sct.id().key_id());
  json_reply.Add("timestamp", sct.timestamp());
  json_reply.Add("extensions", "");
  json_reply.Add("signature", sct.signature());

  output->SendJsonReply(req, HTTP_OK, json_reply);
}


bool HttpHandler::IsNodeStale() const {
  lock_guard<mutex> lock(mutex_);
  return node_is_stale_;
}


void HttpHandler::UpdateNodeStaleness() {
  if (!task_.task()->IsActive()) {
    // We're shutting down, just return.
    return;
  }

  const bool node_is_stale(controller_->NodeIsStale());
  {
    lock_guard<mutex> lock(mutex_);
    node_is_stale_ = node_is_stale;
  }

  event_base_->Delay(seconds(FLAGS_staleness_check_delay_secs),
                     task_.task()->AddChild(
                         bind(&HttpHandler::UpdateNodeStaleness, this)));
}
