#include "server/handler.h"

#include <algorithm>
#include <memory>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <map>
#include <stdlib.h>
#include <utility>
#include <vector>

#include "log/cert.h"
#include "log/cert_checker.h"
#include "log/frontend.h"
#include "log/log_lookup.h"
#include "log/logged_certificate.h"
#include "util/json_wrapper.h"
#include "util/thread_pool.h"

using cert_trans::Cert;
using cert_trans::CertChain;
using cert_trans::CertChecker;
using cert_trans::HttpHandler;
using cert_trans::LoggedCertificate;
using ct::ShortMerkleAuditProof;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;
using std::bind;
using std::make_pair;
using std::make_shared;
using std::multimap;
using std::placeholders::_1;
using std::shared_ptr;
using std::string;
using std::unique_ptr;
using std::vector;

DEFINE_int32(max_leaf_entries_per_response, 1000,
             "Maximum number of entries "
             "to put in the response of a get-entries request.");

namespace {


const char kJsonContentType[] = "application/json; charset=ISO-8859-1";


void SendJsonReply(evhttp_request* req, int http_status,
                   const JsonObject& json) {
  CHECK_EQ(evhttp_add_header(evhttp_request_get_output_headers(req),
                             "Content-Type", kJsonContentType),
           0);
  CHECK_GT(evbuffer_add_printf(evhttp_request_get_output_buffer(req), "%s",
                               json.ToString()),
           0);

  evhttp_send_reply(req, http_status, /*reason*/ NULL, /*databuf*/ NULL);
}


void SendError(evhttp_request* req, int http_status, const string& error_msg) {
  JsonObject json_reply;
  json_reply.Add("error_message", error_msg);
  json_reply.AddBoolean("success", false);

  SendJsonReply(req, http_status, json_reply);
}


bool ExtractChain(evhttp_request* req, CertChain* chain) {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
    SendError(req, HTTP_BADMETHOD, "Method not allowed.");
    return false;
  }

  // TODO(pphaneuf): Should we check that Content-Type says
  // "application/json", as recommended by RFC4627?
  JsonObject json_body(evhttp_request_get_input_buffer(req));
  if (!json_body.Ok() || !json_body.IsType(json_type_object)) {
    SendError(req, HTTP_BADREQUEST, "Unable to parse provided JSON.");
    return false;
  }

  JsonArray json_chain(json_body, "chain");
  if (!json_chain.Ok()) {
    SendError(req, HTTP_BADREQUEST, "Unable to parse provided JSON.");
    return false;
  }

  VLOG(1) << "ExtractChain chain:\n" << json_chain.DebugString();

  for (int i = 0; i < json_chain.Length(); ++i) {
    JsonString json_cert(json_chain, i);
    if (!json_cert.Ok()) {
      SendError(req, HTTP_BADREQUEST, "Unable to parse provided JSON.");
      return false;
    }

    unique_ptr<Cert> cert(new Cert);
    cert->LoadFromDerString(json_cert.FromBase64());
    if (!cert->IsLoaded()) {
      SendError(req, HTTP_BADREQUEST, "Unable to parse provided chain.");
      return false;
    }

    chain->AddCert(cert.release());
  }

  return true;
}


void AddChainReply(evhttp_request* req, SubmitResult result,
                   const SignedCertificateTimestamp& sct) {
  if (result != ADDED && result != DUPLICATE) {
    const string error(Frontend::SubmitResultString(result));
    VLOG(1) << "error adding chain: " << error;
    SendError(req, HTTP_BADREQUEST, error);
    return;
  }

  JsonObject json_reply;
  json_reply.Add("sct_version", static_cast<int64_t>(0));
  json_reply.AddBase64("id", sct.id().key_id());
  json_reply.Add("timestamp", sct.timestamp());
  json_reply.Add("extensions", "");
  json_reply.Add("signature", sct.signature());

  SendJsonReply(req, HTTP_OK, json_reply);
}


multimap<string, string> ParseQuery(evhttp_request* req) {
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


bool GetParam(const multimap<string, string>& query, const string& param,
              string* value) {
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
// FIXME: at least some parameters are strictly 64 bit - we should get
// the right size.
int GetIntParam(const multimap<string, string>& query, const string& param) {
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


}  // namespace


HttpHandler::HttpHandler(LogLookup<LoggedCertificate>* log_lookup,
                         const ReadOnlyDatabase<LoggedCertificate>* db,
                         const CertChecker* cert_checker, Frontend* frontend,
                         ThreadPool* pool)
    : log_lookup_(CHECK_NOTNULL(log_lookup)),
      db_(CHECK_NOTNULL(db)),
      cert_checker_(CHECK_NOTNULL(cert_checker)),
      frontend_(frontend),
      pool_(CHECK_NOTNULL(pool)) {
}


void HttpHandler::Add(libevent::HttpServer* server) {
  // TODO(pphaneuf): An optional prefix might be nice?
  // TODO(pphaneuf): Find out which methods are CPU intensive enough
  // that they should be spun off to the thread pool.
  CHECK(server->AddHandler("/ct/v1/get-entries",
                           bind(&HttpHandler::GetEntries, this, _1)));
  CHECK(server->AddHandler("/ct/v1/get-roots",
                           bind(&HttpHandler::GetRoots, this, _1)));
  CHECK(server->AddHandler("/ct/v1/get-proof-by-hash",
                           bind(&HttpHandler::GetProof, this, _1)));
  CHECK(server->AddHandler("/ct/v1/get-sth",
                           bind(&HttpHandler::GetSTH, this, _1)));
  CHECK(server->AddHandler("/ct/v1/get-sth-consistency",
                           bind(&HttpHandler::GetConsistency, this, _1)));

  if (frontend_) {
    CHECK(server->AddHandler("/ct/v1/add-chain",
                             bind(&HttpHandler::AddChain, this, _1)));
    CHECK(server->AddHandler("/ct/v1/add-pre-chain",
                             bind(&HttpHandler::AddPreChain, this, _1)));
  }
}


void HttpHandler::GetEntries(evhttp_request* req) const {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET)
    return SendError(req, HTTP_BADMETHOD, "Method not allowed.");

  const multimap<string, string> query(ParseQuery(req));

  const int tree_size(log_lookup_->GetSTH().tree_size());
  const int start(GetIntParam(query, "start"));
  if (start < 0 || start >= tree_size) {
    return SendError(req, HTTP_BADREQUEST,
                     "Missing or invalid \"start\" parameter.");
  }

  int end(GetIntParam(query, "end"));
  if (end < start) {
    return SendError(req, HTTP_BADREQUEST,
                     "Missing or invalid \"end\" parameter.");
  }

  // If a bigger tree size than what we have has been requested, we'll
  // send what we have.
  // TODO(pphaneuf): The "start < 0 || start >= tree_size" test above
  // catches the case where the tree is empty (and return an error),
  // we should return an empty result instead.
  end = std::min(end, tree_size - 1);

  // Limit the number of entries returned in a single request.
  end = std::min(end, start + FLAGS_max_leaf_entries_per_response);

  pool_->Add(bind(&HttpHandler::BlockingGetEntries, this, req, start, end));
}


void HttpHandler::GetRoots(evhttp_request* req) const {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
    SendError(req, HTTP_BADMETHOD, "Method not allowed.");
  }

  JsonArray roots;
  multimap<string, const Cert*>::const_iterator it;
  for (it = cert_checker_->GetTrustedCertificates().begin();
       it != cert_checker_->GetTrustedCertificates().end(); ++it) {
    string cert;
    if (it->second->DerEncoding(&cert) != Cert::TRUE) {
      LOG(ERROR) << "Cert encoding failed";
      SendError(req, HTTP_INTERNAL, "Serialisation failed.");
      return;
    }
    roots.AddBase64(cert);
  }

  JsonObject json_reply;
  json_reply.Add("certificates", roots);

  SendJsonReply(req, HTTP_OK, json_reply);
}


void HttpHandler::GetProof(evhttp_request* req) const {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET)
    SendError(req, HTTP_BADMETHOD, "Method not allowed.");

  const multimap<string, string> query(ParseQuery(req));

  string b64_hash;
  if (!GetParam(query, "hash", &b64_hash)) {
    return SendError(req, HTTP_BADREQUEST,
                     "Missing or invalid \"hash\" parameter.");
  }

  const string hash(util::FromBase64(b64_hash.c_str()));
  if (hash.empty()) {
    return SendError(req, HTTP_BADREQUEST, "Invalid \"hash\" parameter.");
  }

  const int tree_size(GetIntParam(query, "tree_size"));
  if (tree_size < 0 ||
      static_cast<uint64_t>(tree_size) > log_lookup_->GetSTH().tree_size()) {
    return SendError(req, HTTP_BADREQUEST,
                     "Missing or invalid \"tree_size\" parameter.");
  }

  ShortMerkleAuditProof proof;
  if (log_lookup_->AuditProof(hash, tree_size, &proof) !=
      LogLookup<LoggedCertificate>::OK) {
    return SendError(req, HTTP_BADREQUEST, "Couldn't find hash.");
  }

  JsonArray json_audit;
  for (int i = 0; i < proof.path_node_size(); ++i) {
    json_audit.AddBase64(proof.path_node(i));
  }

  JsonObject json_reply;
  json_reply.Add("leaf_index", proof.leaf_index());
  json_reply.Add("audit_path", json_audit);

  SendJsonReply(req, HTTP_OK, json_reply);
}


void HttpHandler::GetSTH(evhttp_request* req) const {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET)
    SendError(req, HTTP_BADMETHOD, "Method not allowed.");

  const SignedTreeHead& sth(log_lookup_->GetSTH());

  VLOG(1) << "SignedTreeHead:\n" << sth.DebugString();

  JsonObject json_reply;
  json_reply.Add("tree_size", sth.tree_size());
  json_reply.Add("timestamp", sth.timestamp());
  json_reply.AddBase64("sha256_root_hash", sth.sha256_root_hash());
  json_reply.Add("tree_head_signature", sth.signature());

  VLOG(1) << "GetSTH:\n" << json_reply.DebugString();

  SendJsonReply(req, HTTP_OK, json_reply);
}


void HttpHandler::GetConsistency(evhttp_request* req) const {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
    SendError(req, HTTP_BADMETHOD, "Method not allowed.");
  }

  const multimap<string, string> query(ParseQuery(req));

  const int first(GetIntParam(query, "first"));
  if (first < 0) {
    return SendError(req, HTTP_BADREQUEST,
                     "Missing or invalid \"first\" parameter.");
  }

  const int second(GetIntParam(query, "second"));
  if (second < first) {
    return SendError(req, HTTP_BADREQUEST,
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

  SendJsonReply(req, HTTP_OK, json_reply);
}


void HttpHandler::AddChain(evhttp_request* req) {
  const shared_ptr<CertChain> chain(make_shared<CertChain>());
  if (!ExtractChain(req, chain.get())) {
    return;
  }

  pool_->Add(bind(&HttpHandler::BlockingAddChain, this, req, chain));
}


void HttpHandler::AddPreChain(evhttp_request* req) {
  const shared_ptr<PreCertChain> chain(make_shared<PreCertChain>());
  if (!ExtractChain(req, chain.get())) {
    return;
  }

  pool_->Add(bind(&HttpHandler::BlockingAddPreChain, this, req, chain));
}


void HttpHandler::BlockingGetEntries(evhttp_request* req, int start,
                                     int end) const {
  JsonArray json_entries;
  for (int i = start; i <= end; ++i) {
    LoggedCertificate cert;

    if (db_->LookupByIndex(i, &cert) !=
        ReadOnlyDatabase<LoggedCertificate>::LOOKUP_OK) {
      return SendError(req, HTTP_BADREQUEST, "Entry not found.");
    }

    string leaf_input;
    string extra_data;
    if (!cert.SerializeForLeaf(&leaf_input) ||
        !cert.SerializeExtraData(&extra_data)) {
      return SendError(req, HTTP_INTERNAL, "Serialization failed.");
    }

    JsonObject json_entry;
    json_entry.AddBase64("leaf_input", leaf_input);
    json_entry.AddBase64("extra_data", extra_data);

    json_entries.Add(&json_entry);
  }

  JsonObject json_reply;
  json_reply.Add("entries", json_entries);

  SendJsonReply(req, HTTP_OK, json_reply);
}


void HttpHandler::BlockingAddChain(evhttp_request* req,
                                   const shared_ptr<CertChain>& chain) const {
  SignedCertificateTimestamp sct;

  AddChainReply(req, CHECK_NOTNULL(frontend_)
                         ->QueueX509Entry(CHECK_NOTNULL(chain.get()), &sct),
                sct);
}


void HttpHandler::BlockingAddPreChain(
    evhttp_request* req, const shared_ptr<PreCertChain>& chain) const {
  SignedCertificateTimestamp sct;

  AddChainReply(req, CHECK_NOTNULL(frontend_)
                         ->QueuePreCertEntry(CHECK_NOTNULL(chain.get()), &sct),
                sct);
}
