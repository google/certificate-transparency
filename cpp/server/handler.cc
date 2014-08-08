#include "server/handler.h"

#include <glog/logging.h>

#include "log/cert.h"
#include "log/logged_certificate.h"
#include "util/json_wrapper.h"

using boost::network::uri::query_map;
using boost::network::uri::uri;
using cert_trans::HttpHandler;
using ct::Cert;
using std::string;


void HttpHandler::operator() (server::request const &request,
                              server::response &response) {
  VLOG(1) << "[" << string(source(request))
          << "]: source = " << request.source
          << " destination = " << request.destination
          << " method = " << request.method
          << " status = " << response.status << '\n';

  // This is kinda incredibly dumb, but cpp-netlib can't do any
  // better.
  uri uri(string("http://x") + request.destination);
  string path = uri.path();

  VLOG(1) << "path = " << path;

  if (request.method == "GET") {
    if (path == "/ct/v1/get-entries")
      GetEntries(response, uri);
    else if (path == "/ct/v1/get-roots")
      GetRoots(response);
    else if (path == "/ct/v1/get-proof-by-hash")
      GetProof(response, uri);
    else if (path == "/ct/v1/get-sth")
      GetSTH(response);
    else if (path == "/ct/v1/get-sth-consistency")
      GetConsistency(response, uri);
    else
      response = server::response::stock_reply(server::response::not_found,
                                               "Not found");
  } else if (request.method == "POST") {
    if (path == "/ct/v1/add-chain")
      AddChain(response, request.body);
    else if (path == "/ct/v1/add-pre-chain")
      AddPreChain(response, request.body);
    else
      response = server::response::stock_reply(server::response::not_found,
                                               "Not found");
  }

  VLOG(1) << "Response: status = " << response.status << ", content = "
          << response.content;
}


void HttpHandler::log(const std::string &err) {
  LOG(ERROR) << err;
}


void HttpHandler::BadRequest(server::response &response, const char *msg) {
  response.status = server::response::bad_request;
  response.content = msg;
}


void HttpHandler::GetRoots(server::response &response) const {
  std::multimap<string, const ct::Cert*>::const_iterator it
      = manager_->GetRoots().begin();

  JsonArray roots;
  for (; it != manager_->GetRoots().end(); ++it) {
    string cert;
    if (it->second->DerEncoding(&cert) != Cert::TRUE) {
      LOG(ERROR) << "Cert encoding failed";
      BadRequest(response, "Serialisation failed");
      return;
    }
    roots.AddBase64(cert);
  }

  JsonObject jsend;
  jsend.Add("certificates", roots);

  response.status = server::response::ok;
  response.content = jsend.ToString();
}


void HttpHandler::GetEntries(server::response &response,
                             const uri &uri) const {
  std::map<string, string> qmap;
  query_map(uri, qmap);

  if (qmap.find("start") == qmap.end() || qmap.find("end") == qmap.end()) {
    BadRequest(response, "Bad parameters");
    return;
  }

  size_t start = atoi(qmap["start"].c_str());
  size_t end = atoi(qmap["end"].c_str());

  VLOG(0) << "start = " << start << " end = " << end;

  JsonArray entries;
  for (size_t n = start; n <= end; ++n) {
    ct::LoggedCertificate cert;
    manager_->GetEntry(n, &cert);

    string leaf_input;
    if (!cert.SerializeForLeaf(&leaf_input)) {
      BadRequest(response, "Serialisation failed");
      return;
    }
    JsonObject jentry;
    jentry.Add("leaf_input", util::ToBase64(leaf_input));

    string extra_data;
    if (!cert.SerializeExtraData(&extra_data)) {
      BadRequest(response, "Serialisation failed");
      return;
    }

    jentry.Add("extra_data", util::ToBase64(extra_data));

    entries.Add(&jentry);
  }

  JsonObject jsend;
  jsend.Add("entries", entries);

  response.status = server::response::ok;
  response.content = jsend.ToString();
}


void HttpHandler::GetConsistency(server::response &response, const uri &uri) {
  std::map<string, string> qmap;
  query_map(uri, qmap);

  if (qmap.find("first") == qmap.end() || qmap.find("second") == qmap.end()) {
    response.status = server::response::bad_request;
    response.content = "Bad parameters";
    return;
  }

  size_t first = atoi(qmap["first"].c_str());
  size_t second = atoi(qmap["second"].c_str());

  std::vector<string> consistency = manager_->GetConsistency(first, second);

  JsonArray jcons;
  for (std::vector<string>::const_iterator i = consistency.begin();
       i != consistency.end(); ++i)
    jcons.AddBase64(*i);

  JsonObject jsend;
  jsend.Add("consistency", jcons);

  response.status = server::response::ok;
  response.content = jsend.ToString();
}


void HttpHandler::GetProof(server::response &response, const uri &uri) {
  std::map<string, string> qmap;
  query_map(uri, qmap);
  string b64hash = boost::network::uri::decoded(qmap["hash"]);
  size_t tree_size = atoi(qmap["tree_size"].c_str());

  const ct::SignedTreeHead &sth = manager_->GetSTH();
  if (tree_size > sth.tree_size()) {
    response.status = server::response::bad_request;
    response.content = "Tree is not that big";
    return;
  }

  ct::ShortMerkleAuditProof proof;
  CTLogManager::LookupReply reply
      = manager_->QueryAuditProof(util::FromBase64(b64hash.c_str()),
                                  tree_size, &proof);
  if (reply == CTLogManager::NOT_FOUND) {
    response.status = server::response::bad_request;
    response.content = "Couldn't find hash";
    return;
  }

  CHECK_EQ(CTLogManager::MERKLE_AUDIT_PROOF, reply);

  JsonArray audit;
  for (int n = 0; n < proof.path_node_size(); ++n)
    audit.AddBase64(proof.path_node(n));

  JsonObject jsend;
  jsend.Add("leaf_index", proof.leaf_index());
  jsend.Add("audit_path", audit);

  response.status = server::response::ok;
  response.content = jsend.ToString();
}


void HttpHandler::GetSTH(server::response &response) {
  const ct::SignedTreeHead &sth = manager_->GetSTH();
  response.status = server::response::ok;

  VLOG(1) << "STH is " << sth.DebugString();

  JsonObject jsend;
  jsend.Add("tree_size", sth.tree_size());
  jsend.Add("timestamp", sth.timestamp());
  jsend.AddBase64("sha256_root_hash", sth.sha256_root_hash());
  jsend.Add("tree_head_signature", sth.signature());

  response.content = jsend.ToString();
}


void HttpHandler::AddChain(server::response &response,
                           const std::string &body) {
  ct::CertChain chain;
  AddChain(response, body, &chain, NULL);
}


void HttpHandler::AddPreChain(server::response &response,
                              const std::string &body) {
  ct::PreCertChain chain;
  AddChain(response, body, NULL, &chain);
}


void HttpHandler::AddChain(server::response &response, const std::string &body,
                           ct::CertChain *chain, ct::PreCertChain *prechain) {
  if (!ExtractChain(response, chain != NULL ? chain : prechain, body))
    return;

  ct::SignedCertificateTimestamp sct;
  string error;
  CTLogManager::LogReply result = manager_->SubmitEntry(chain, prechain, &sct,
                                                        &error);

  ProcessChainResult(response, result, error, sct);
}


bool HttpHandler::ExtractChain(server::response &response,
                               ct::CertChain *chain, const string &body) {
  JsonObject jbody(body);

  JsonArray jchain(jbody, "chain");
  if (!jchain.Ok()) {
    response.status = server::response::bad_request;
    response.content = "Couldn't extract chain";
    LOG(INFO) << "Couldn't extract chain from " << body;
    return false;
  }

  for (int n = 0; n < jchain.Length(); ++n) {
    JsonString jcert(jchain, n);
    string cert_der = jcert.FromBase64();
    X509 *x509 = NULL;
    const unsigned char *in
        = reinterpret_cast<const unsigned char *>(cert_der.data());
    x509 = d2i_X509(&x509, &in, cert_der.length());
    if (x509 == NULL) {
      response.status = server::response::bad_request;
      response.content = "Couldn't decode certificate";
      return false;
    }
    ct::Cert *cert = new ct::Cert(x509);
    if (!cert->IsLoaded()) {
      delete cert;
      response.status = server::response::bad_request;
      response.content = "Couldn't load certificate";
      LOG(INFO) << "Couldn't load certificate " << jcert.Value();
      return false;
    }
    chain->AddCert(cert);
  }

  return true;
}


void HttpHandler::ProcessChainResult(
    server::response &response, CTLogManager::LogReply result,
    const string &error, const ct::SignedCertificateTimestamp &sct) {
  LOG(INFO) << "Chain added, result = " << result << ", error = " << error;

  JsonObject jsend;
  if (result == CTLogManager::REJECT) {
    jsend.AddBoolean("success", false);
    jsend.Add("reason",error);
    response.status = server::response::bad_request;
  } else {
    jsend.Add("sct_version", (int64_t)0);
    jsend.AddBase64("id", sct.id().key_id());
    jsend.Add("timestamp",sct.timestamp());
    jsend.Add("extensions", "");
    jsend.Add("signature", sct.signature());
    response.status = server::response::ok;
  }
  response.content = jsend.ToString();
}
