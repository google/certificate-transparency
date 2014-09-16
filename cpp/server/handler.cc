#include "server/handler.h"

#include <boost/bind.hpp>
#include <boost/make_shared.hpp>
#include <boost/scoped_array.hpp>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <glog/logging.h>
#include <map>
#include <stdlib.h>
#include <utility>
#include <vector>

#include "log/cert.h"
#include "log/logged_certificate.h"
#include "util/json_wrapper.h"
#include "util/thread_pool.h"

using boost::bind;
using boost::make_shared;
using boost::scoped_array;
using boost::shared_ptr;
using cert_trans::CTLogManager;
using cert_trans::HttpHandler;
using ct::Cert;
using ct::LoggedCertificate;
using ct::ShortMerkleAuditProof;
using std::make_pair;
using std::multimap;
using std::string;
using std::vector;

namespace {


const char kJsonContentType[] = "application/json; charset=ISO-8859-1";


void SendJsonReply(evhttp_request *req, int http_status,
                   const JsonObject &json) {
  CHECK_EQ(evhttp_add_header(
      evhttp_request_get_output_headers(req), "Content-Type",
      kJsonContentType), 0);
  CHECK_GT(evbuffer_add_printf(evhttp_request_get_output_buffer(req),
                               "%s", json.ToString()), 0);

  evhttp_send_reply(req, http_status, /*reason*/ NULL, /*databuf*/ NULL);
}


void SendError(evhttp_request *req, int http_status, const string &error_msg) {
  JsonObject json_reply;
  json_reply.Add("error_message", error_msg);
  json_reply.AddBoolean("success", false);

  SendJsonReply(req, http_status, json_reply);
}


json_object *ParseJsonBuffer(evbuffer *const input_buffer) {
  // Calling evbuffer_peek with a NULL "vec_out" makes it a query for
  // how many evbuffer_iovec entries you would need.
  const int num_vec(evbuffer_peek(input_buffer, -1, /*start_at*/ NULL,
                                  /*vec_out*/ NULL, 0));
  const scoped_array<evbuffer_iovec> chunks(new evbuffer_iovec[num_vec]);
  CHECK_EQ(evbuffer_peek(input_buffer, -1, /*start_at*/ NULL, chunks.get(),
                         num_vec), num_vec);

  // TODO(pphaneuf): We just want a deleter, but unique_ptr is not
  // available to us yet (C++11).
  const shared_ptr<json_tokener> tokener(json_tokener_new(),
                                         &json_tokener_free);
  json_object *json(NULL);
  bool error(false);
  size_t num_read(0);
  for (int i = 0; i < num_vec; ++i) {
    num_read += chunks[i].iov_len;
    // Only parse if we're still looking for an object and have not
    // encountered an error.
    if (!json && !error) {
      // This function can be called repeatedly with each chunk of
      // data. It keep its state in "*tokener", and will return a
      // non-NULL value once it finds a full object. If it returns
      // NULL and the error is "json_tokener_continue", this simply
      // means that it hasn't yet found an object, we just need to
      // keep calling it with more data.
      json = json_tokener_parse_ex(tokener.get(),
                                   static_cast<char *>(chunks[i].iov_base),
                                   chunks[i].iov_len);

      if (!json &&
          json_tokener_get_error(tokener.get()) != json_tokener_continue) {
        VLOG(1) << "json_tokener_parse_ex: " << json_tokener_error_desc(
            json_tokener_get_error(tokener.get()));
        // This will prevent further parsing attempts, but we won't
        // break, so we can get the full amount of data for "num_read"
        // and drain it all. At this point, "json" is NULL, and since
        // we won't try to parse any further, it will remain so until
        // this function returns.
        error = true;
      }
    }
  }
  CHECK_EQ(evbuffer_drain(input_buffer, num_read), 0);

  return json;
}


bool ExtractChain(evhttp_request *req, ct::CertChain *chain) {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
    SendError(req, HTTP_BADMETHOD, "Method not allowed.");
    return false;
  }

  // TODO(pphaneuf): Should we check that Content-Type says
  // "application/json", as recommended by RFC4627?
  JsonObject json_body(ParseJsonBuffer(evhttp_request_get_input_buffer(req)));
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

    // TODO(pphaneuf): I would have used unique_ptr here to release
    // the ownership, but we can't use it yet (C++11).
    ct::Cert *const cert(new Cert);
    cert->LoadFromDerString(json_cert.FromBase64());
    if (!cert->IsLoaded()) {
      delete cert;
      SendError(req, HTTP_BADREQUEST, "Unable to parse provided chain.");
      return false;
    }

    chain->AddCert(cert);
  }

  return true;
}


void AddChainReply(evhttp_request *req, CTLogManager::LogReply result,
                   const ct::SignedCertificateTimestamp &sct,
                   const string &error) {
  if (result != CTLogManager::SIGNED_CERTIFICATE_TIMESTAMP) {
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


multimap<string, string> ParseQuery(evhttp_request *req) {
  evkeyvalq keyval;
  multimap<string, string> retval;

  // We return an empty result in case of a parsing error.
  if (evhttp_parse_query_str(evhttp_uri_get_query(
          evhttp_request_get_evhttp_uri(req)), &keyval) == 0) {
    for (evkeyval *i = keyval.tqh_first; i; i = i->next.tqe_next) {
      retval.insert(make_pair(i->key, i->value));
    }
  }

  return retval;
}


bool GetParam(const multimap<string, string> &query, const string &param,
              string *value) {
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
int GetIntParam(const multimap<string, string> &query, const string &param) {
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


HttpHandler::HttpHandler(CTLogManager *manager, ThreadPool *pool)
    : manager_(CHECK_NOTNULL(manager)),
      pool_(CHECK_NOTNULL(pool)) {
}


void HttpHandler::Add(libevent::HttpServer *server) {
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
  CHECK(server->AddHandler("/ct/v1/add-chain",
                           bind(&HttpHandler::AddChain, this, _1)));
  CHECK(server->AddHandler("/ct/v1/add-pre-chain",
                           bind(&HttpHandler::AddPreChain, this, _1)));
}


void HttpHandler::GetEntries(evhttp_request *req) const {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET)
    return SendError(req, HTTP_BADMETHOD, "Method not allowed.");

  const multimap<string, string> query(ParseQuery(req));

  const int tree_size(manager_->GetSTH().tree_size());
  const int start(GetIntParam(query, "start"));
  if (start < 0 || start >= tree_size) {
    return SendError(req, HTTP_BADREQUEST,
                     "Missing or invalid \"start\" parameter.");
  }

  const int end(GetIntParam(query, "end"));
  if (end < start || end >= tree_size) {
    return SendError(req, HTTP_BADREQUEST,
                     "Missing or invalid \"end\" parameter.");
  }

  JsonArray json_entries;
  for (int i = start; i <= end; ++i) {
    LoggedCertificate cert;
    if (manager_->GetEntry(i, &cert) != CTLogManager::FOUND) {
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


void HttpHandler::GetRoots(evhttp_request *req) const {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
    SendError(req, HTTP_BADMETHOD, "Method not allowed.");
  }

  JsonArray roots;
  multimap<string, const ct::Cert *>::const_iterator it;
  for (it = manager_->GetRoots().begin(); it != manager_->GetRoots().end();
       ++it) {
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


void HttpHandler::GetProof(evhttp_request *req) const {
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
  if (tree_size < 0
      || static_cast<uint64_t>(tree_size) > manager_->GetSTH().tree_size()) {
    return SendError(req, HTTP_BADREQUEST,
                     "Missing or invalid \"tree_size\" parameter.");
  }

  ShortMerkleAuditProof proof;
  if (manager_->QueryAuditProof(hash, tree_size, &proof)
      != CTLogManager::MERKLE_AUDIT_PROOF) {
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


void HttpHandler::GetSTH(evhttp_request *req) const {
  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET)
    SendError(req, HTTP_BADMETHOD, "Method not allowed.");

  const ct::SignedTreeHead &sth(manager_->GetSTH());

  VLOG(1) << "SignedTreeHead:\n" << sth.DebugString();

  JsonObject json_reply;
  json_reply.Add("tree_size", sth.tree_size());
  json_reply.Add("timestamp", sth.timestamp());
  json_reply.AddBase64("sha256_root_hash", sth.sha256_root_hash());
  json_reply.Add("tree_head_signature", sth.signature());

  VLOG(1) << "GetSTH:\n" << json_reply.DebugString();

  SendJsonReply(req, HTTP_OK, json_reply);
}


void HttpHandler::GetConsistency(evhttp_request *req) const {
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

  const vector<string> consistency(manager_->GetConsistency(first, second));
  JsonArray json_cons;
  for (vector<string>::const_iterator it = consistency.begin();
       it != consistency.end(); ++it) {
    json_cons.AddBase64(*it);
  }

  JsonObject json_reply;
  json_reply.Add("consistency", json_cons);

  SendJsonReply(req, HTTP_OK, json_reply);
}


void HttpHandler::AddChain(evhttp_request *req) {
  const shared_ptr<ct::CertChain> chain(make_shared<ct::CertChain>());
  if (!ExtractChain(req, chain.get())) {
    return;
  }

  pool_->Add(bind(&HttpHandler::BlockingAddChain, this, req, chain));
}


void HttpHandler::AddPreChain(evhttp_request *req) {
  const shared_ptr<ct::PreCertChain> chain(make_shared<ct::PreCertChain>());
  if (!ExtractChain(req, chain.get())) {
    return;
  }

  pool_->Add(bind(&HttpHandler::BlockingAddPreChain, this, req, chain));
}


void HttpHandler::BlockingAddChain(
    evhttp_request *req, const shared_ptr<ct::CertChain> &chain) const {
  ct::SignedCertificateTimestamp sct;
  string error;
  const CTLogManager::LogReply result(
      manager_->SubmitEntry(chain.get(), /*prechain*/ NULL, &sct, &error));

  AddChainReply(req, result, sct, error);
}


void HttpHandler::BlockingAddPreChain(
    evhttp_request *req, const shared_ptr<ct::PreCertChain> &chain) const {
  ct::SignedCertificateTimestamp sct;
  string error;
  const CTLogManager::LogReply result(
      manager_->SubmitEntry(/*chain*/ NULL, chain.get(), &sct, &error));

  AddChainReply(req, result, sct, error);
}
