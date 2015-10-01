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
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
    return output_->SendError(req, HTTP_BADMETHOD, "Method not allowed.");
  }

  const multimap<string, string> query(ParseQuery(req));

  const int64_t start(GetIntParam(query, "start"));
  if (start < 0) {
    return output_->SendError(req, HTTP_BADREQUEST,
                              "Missing or invalid \"start\" parameter.");
  }

  int64_t end(GetIntParam(query, "end"));
  if (end < start) {
    return output_->SendError(req, HTTP_BADREQUEST,
                              "Missing or invalid \"end\" parameter.");
  }

  // Limit the number of entries returned in a single request.
  end = std::min(end, start + GetMaxLeafEntriesPerResponse());

  // Sekrit parameter to indicate that SCTs should be included too.
  // This is non-standard, and is only used internally by other log nodes when
  // "following" nodes with more data.
  const bool include_scts(GetBoolParam(query, "include_scts"));

  BlockingGetEntries(req, start, end, include_scts);
}


void HttpHandlerV2::GetRoots(evhttp_request* req) const {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
    return output_->SendError(req, HTTP_BADMETHOD, "Method not allowed.");
  }

  JsonArray roots;
  multimap<string, const Cert*>::const_iterator it;
  for (it = cert_checker_->GetTrustedCertificates().begin();
       it != cert_checker_->GetTrustedCertificates().end(); ++it) {
    string cert;
    if (it->second->DerEncoding(&cert) != util::Status::OK) {
      LOG(ERROR) << "Cert encoding failed";
      return output_->SendError(req, HTTP_INTERNAL, "Serialisation failed.");
    }
    roots.AddBase64(cert);
  }

  JsonObject json_reply;
  json_reply.Add("certificates", roots);

  output_->SendJsonReply(req, HTTP_OK, json_reply);
}


void HttpHandlerV2::GetProof(evhttp_request* req) const {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
    return output_->SendError(req, HTTP_BADMETHOD, "Method not allowed.");
  }

  const multimap<string, string> query(ParseQuery(req));

  string b64_hash;
  if (!GetParam(query, "hash", &b64_hash)) {
    return output_->SendError(req, HTTP_BADREQUEST,
                              "Missing or invalid \"hash\" parameter.");
  }

  const string hash(util::FromBase64(b64_hash.c_str()));
  if (hash.empty()) {
    return output_->SendError(req, HTTP_BADREQUEST,
                              "Invalid \"hash\" parameter.");
  }

  const int64_t tree_size(GetIntParam(query, "tree_size"));
  if (tree_size < 0 ||
      static_cast<int64_t>(tree_size) > log_lookup_->GetSTH().tree_size()) {
    return output_->SendError(req, HTTP_BADREQUEST,
                              "Missing or invalid \"tree_size\" parameter.");
  }

  ShortMerkleAuditProof proof;
  if (log_lookup_->AuditProof(hash, tree_size, &proof) !=
      LogLookup<LoggedCertificate>::OK) {
    return output_->SendError(req, HTTP_BADREQUEST, "Couldn't find hash.");
  }

  JsonArray json_audit;
  for (int i = 0; i < proof.path_node_size(); ++i) {
    json_audit.AddBase64(proof.path_node(i));
  }

  JsonObject json_reply;
  json_reply.Add("leaf_index", proof.leaf_index());
  json_reply.Add("audit_path", json_audit);

  output_->SendJsonReply(req, HTTP_OK, json_reply);
}


void HttpHandlerV2::GetSTH(evhttp_request* req) const {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
    return output_->SendError(req, HTTP_BADMETHOD, "Method not allowed.");
  }

  const SignedTreeHead& sth(log_lookup_->GetSTH());

  VLOG(2) << "SignedTreeHead:\n" << sth.DebugString();

  JsonObject json_reply;
  json_reply.Add("tree_size", sth.tree_size());
  json_reply.Add("timestamp", sth.timestamp());
  json_reply.AddBase64("sha256_root_hash", sth.sha256_root_hash());
  json_reply.Add("tree_head_signature", sth.signature());

  VLOG(2) << "GetSTH:\n" << json_reply.DebugString();

  output_->SendJsonReply(req, HTTP_OK, json_reply);
}


void HttpHandlerV2::GetConsistency(evhttp_request* req) const {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
    return output_->SendError(req, HTTP_BADMETHOD, "Method not allowed.");
  }

  const multimap<string, string> query(ParseQuery(req));

  const int64_t first(GetIntParam(query, "first"));
  if (first < 0) {
    return output_->SendError(req, HTTP_BADREQUEST,
                              "Missing or invalid \"first\" parameter.");
  }

  const int64_t second(GetIntParam(query, "second"));
  if (second < first) {
    return output_->SendError(req, HTTP_BADREQUEST,
                              "Missing or invalid \"second\" parameter.");
  }

  const vector<string> consistency(
      log_lookup_->ConsistencyProof(first, second));
  JsonArray json_cons;
  for (vector<string>::const_iterator it = consistency.begin();
       it != consistency.end(); ++it) {
    json_cons.AddBase64(*it);
  }

  JsonObject json_reply;
  json_reply.Add("consistency", json_cons);

  output_->SendJsonReply(req, HTTP_OK, json_reply);
}


void HttpHandlerV2::AddChain(evhttp_request* req) {
  const shared_ptr<CertChain> chain(make_shared<CertChain>());
  if (!ExtractChain(output_, req, chain.get())) {
    return;
  }

  pool_->Add(bind(&HttpHandler::BlockingAddChain, this, req, chain));
}


void HttpHandlerV2::BlockingGetEntries(evhttp_request* req, int64_t start,
                                       int64_t end, bool include_scts) const {
  JsonArray json_entries;
  auto it(db_->ScanEntries(start));
  for (int64_t i = start; i <= end; ++i) {
    LoggedCertificate cert;

    if (!it->GetNextEntry(&cert) || cert.sequence_number() != i) {
      break;
    }

    string leaf_input;
    string extra_data;
    string sct_data;
    if (!cert.SerializeForLeaf(&leaf_input) ||
        !cert.SerializeExtraData(&extra_data) ||
        (include_scts &&
         Serializer::SerializeSCT(cert.sct(), &sct_data) != Serializer::OK)) {
      LOG(WARNING) << "Failed to serialize entry @ " << i << ":\n"
                   << cert.DebugString();
      return output_->SendError(req, HTTP_INTERNAL, "Serialization failed.");
    }

    JsonObject json_entry;
    json_entry.AddBase64("leaf_input", leaf_input);
    json_entry.AddBase64("extra_data", extra_data);

    if (include_scts) {
      // This is non-standard, and currently only used by other SuperDuper log
      // nodes when "following" to fetch data from each other:
      json_entry.AddBase64("sct", sct_data);
    }

    json_entries.Add(&json_entry);
  }

  if (json_entries.Length() < 1) {
    return output_->SendError(req, HTTP_BADREQUEST, "Entry not found.");
  }

  JsonObject json_reply;
  json_reply.Add("entries", json_entries);

  output_->SendJsonReply(req, HTTP_OK, json_reply);
}


void HttpHandlerV2::Add(libevent::HttpServer* server) {
  CHECK_NOTNULL(server);
  // TODO(pphaneuf): Find out which methods are CPU intensive enough
  // that they should be spun off to the thread pool.
  const string handler_path_prefix("/ct/v2/");

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
                           bind(&HttpHandlerV2::AddPreChain, this, _1));
  }
}

void HttpHandlerV2::AddPreChain(evhttp_request* req) {
  output_->SendError(req, HTTP_NOTIMPLEMENTED, "Not yet implemented");
}


void HttpHandlerV2::BlockingAddChain(evhttp_request* req,
                                     const shared_ptr<CertChain>& chain) {
  SignedCertificateTimestamp sct;

  AddChainReply(output_, req,
                CHECK_NOTNULL(frontend_)
                    ->QueueX509Entry(CHECK_NOTNULL(chain.get()), &sct),
                sct);
}


void HttpHandlerV2::BlockingAddPreChain(
    evhttp_request* req, const shared_ptr<PreCertChain>& chain) {
  output_->SendError(req, HTTP_NOTIMPLEMENTED, "Not yet implemented");
}

