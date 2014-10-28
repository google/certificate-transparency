#include "client/async_log_client.h"

#include <algorithm>
#include <memory>
#include <glog/logging.h>
#include <iterator>
#include <sstream>

#include "log/cert.h"
#include "proto/serializer.h"
#include "util/json_wrapper.h"
#include "util/libevent_wrapper.h"

namespace libevent = cert_trans::libevent;

using cert_trans::AsyncLogClient;
using cert_trans::Cert;
using cert_trans::CertChain;
using cert_trans::PreCertChain;
using ct::DigitallySigned;
using ct::MerkleAuditProof;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;
using std::back_inserter;
using std::copy;
using std::function;
using std::make_shared;
using std::ostringstream;
using std::placeholders::_1;
using std::shared_ptr;
using std::string;
using std::vector;

namespace {


string UriEncode(const string& input) {
  // TODO(pphaneuf): I just wanted the deleter, so std::unique_ptr
  // would have worked, but it's not available to us (C++11).
  const shared_ptr<char> output(evhttp_uriencode(input.data(), input.size(),
                                                 false),
                                free);

  return output.get();
}


// Do some common checks, calls the callback with the appropriate
// error if something is wrong.
bool SanityCheck(libevent::HttpRequest* req,
                 const AsyncLogClient::Callback& done) {
  if (evhttp_request_get_response_code(req->get()) < 1) {
    done(AsyncLogClient::CONNECT_FAILED);
    return false;
  }

  if (evhttp_request_get_response_code(req->get()) != HTTP_OK) {
    done(AsyncLogClient::UNKNOWN_ERROR);
    return false;
  }

  return true;
}


void DoneGetSTH(libevent::HttpRequest* req, SignedTreeHead* sth,
                const AsyncLogClient::Callback& done) {
  if (!SanityCheck(req, done))
    return;

  JsonObject jresponse(evhttp_request_get_input_buffer(req->get()));
  if (!jresponse.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonInt tree_size(jresponse, "tree_size");
  if (!tree_size.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonInt timestamp(jresponse, "timestamp");
  if (!timestamp.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonString root_hash(jresponse, "sha256_root_hash");
  if (!root_hash.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonString jsignature(jresponse, "tree_head_signature");
  if (!jsignature.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);
  DigitallySigned signature;
  if (Deserializer::DeserializeDigitallySigned(jsignature.FromBase64(),
                                               &signature) != Deserializer::OK)
    return done(AsyncLogClient::BAD_RESPONSE);

  sth->Clear();
  sth->set_version(ct::V1);
  sth->set_tree_size(tree_size.Value());
  sth->set_timestamp(timestamp.Value());
  sth->set_sha256_root_hash(root_hash.FromBase64());
  sth->mutable_signature()->CopyFrom(signature);

  return done(AsyncLogClient::OK);
}


void DoneGetRoots(libevent::HttpRequest* req, vector<shared_ptr<Cert> >* roots,
                  const AsyncLogClient::Callback& done) {
  if (!SanityCheck(req, done))
    return;

  JsonObject jresponse(evhttp_request_get_input_buffer(req->get()));
  if (!jresponse.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonArray jroots(jresponse, "certificates");
  if (!jroots.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  vector<shared_ptr<Cert> > retval;
  for (int i = 0; i < jroots.Length(); ++i) {
    JsonString jcert(jroots, i);
    if (!jcert.Ok())
      return done(AsyncLogClient::BAD_RESPONSE);

    shared_ptr<Cert> cert(make_shared<Cert>());
    const Cert::Status status(cert->LoadFromDerString(jcert.FromBase64()));
    if (status != Cert::TRUE)
      return done(AsyncLogClient::BAD_RESPONSE);

    retval.push_back(cert);
  }

  roots->swap(retval);

  return done(AsyncLogClient::OK);
}


void DoneGetEntries(libevent::HttpRequest* req,
                    vector<AsyncLogClient::Entry>* entries,
                    const AsyncLogClient::Callback& done) {
  if (!SanityCheck(req, done))
    return;

  JsonObject jresponse(evhttp_request_get_input_buffer(req->get()));
  if (!jresponse.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonArray jentries(jresponse, "entries");
  if (!jentries.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  vector<AsyncLogClient::Entry> new_entries;
  new_entries.reserve(jentries.Length());

  for (int n = 0; n < jentries.Length(); ++n) {
    JsonObject entry(jentries, n);
    if (!entry.Ok())
      return done(AsyncLogClient::BAD_RESPONSE);

    JsonString leaf_input(entry, "leaf_input");
    if (!leaf_input.Ok())
      return done(AsyncLogClient::BAD_RESPONSE);

    AsyncLogClient::Entry log_entry;
    if (Deserializer::DeserializeMerkleTreeLeaf(leaf_input.FromBase64(),
                                                &log_entry.leaf) !=
        Deserializer::OK)
      return done(AsyncLogClient::BAD_RESPONSE);

    JsonString extra_data(entry, "extra_data");
    if (!extra_data.Ok())
      return done(AsyncLogClient::BAD_RESPONSE);

    if (log_entry.leaf.timestamped_entry().entry_type() == ct::X509_ENTRY)
      Deserializer::DeserializeX509Chain(extra_data.FromBase64(),
                                         log_entry.entry.mutable_x509_entry());
    else if (log_entry.leaf.timestamped_entry().entry_type() ==
             ct::PRECERT_ENTRY)
      Deserializer::DeserializePrecertChainEntry(
          extra_data.FromBase64(), log_entry.entry.mutable_precert_entry());
    else
      LOG(FATAL) << "Don't understand entry type: "
                 << log_entry.leaf.timestamped_entry().entry_type();

    new_entries.push_back(log_entry);
  }

  entries->reserve(entries->size() + new_entries.size());
  copy(new_entries.begin(), new_entries.end(), back_inserter(*entries));

  return done(AsyncLogClient::OK);
}


void DoneQueryInclusionProof(libevent::HttpRequest* req,
                             const SignedTreeHead& sth,
                             MerkleAuditProof* proof,
                             const AsyncLogClient::Callback& done) {
  if (!SanityCheck(req, done))
    return;

  JsonObject jresponse(evhttp_request_get_input_buffer(req->get()));
  if (!jresponse.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonInt leaf_index(jresponse, "leaf_index");
  if (!leaf_index.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonArray audit_path(jresponse, "audit_path");
  if (!audit_path.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  vector<string> path_nodes;
  for (int n = 0; n < audit_path.Length(); ++n) {
    JsonString path_node(audit_path, n);
    CHECK(path_node.Ok());
    path_nodes.push_back(path_node.FromBase64());
  }

  proof->Clear();
  proof->set_version(ct::V1);
  proof->set_tree_size(sth.tree_size());
  proof->set_timestamp(sth.timestamp());
  proof->mutable_tree_head_signature()->CopyFrom(sth.signature());
  proof->set_leaf_index(leaf_index.Value());
  for (vector<string>::const_iterator it = path_nodes.begin();
       it != path_nodes.end(); ++it) {
    proof->add_path_node(*it);
  }

  return done(AsyncLogClient::OK);
}


void DoneGetSTHConsistency(libevent::HttpRequest* req, vector<string>* proof,
                           const AsyncLogClient::Callback& done) {
  if (!SanityCheck(req, done))
    return;

  JsonObject jresponse(evhttp_request_get_input_buffer(req->get()));
  if (!jresponse.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonArray jproof(jresponse, "consistency");
  if (!jproof.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  vector<string> entries;
  for (int i = 0; i < jproof.Length(); ++i) {
    JsonString entry(jproof, i);
    if (!entry.Ok())
      return done(AsyncLogClient::BAD_RESPONSE);

    entries.push_back(entry.FromBase64());
  }

  proof->reserve(proof->size() + entries.size());
  copy(entries.begin(), entries.end(), back_inserter(*proof));

  return done(AsyncLogClient::OK);
}


void DoneInternalAddChain(libevent::HttpRequest* req,
                          SignedCertificateTimestamp* sct,
                          const AsyncLogClient::Callback& done) {
  if (!SanityCheck(req, done))
    return;

  JsonObject jresponse(evhttp_request_get_input_buffer(req->get()));
  if (!jresponse.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  if (!jresponse.IsType(json_type_object))
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonString id(jresponse, "id");
  if (!id.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonInt timestamp(jresponse, "timestamp");
  if (!timestamp.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonString extensions(jresponse, "extensions");
  if (!extensions.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  JsonString jsignature(jresponse, "signature");
  if (!jsignature.Ok())
    return done(AsyncLogClient::BAD_RESPONSE);

  DigitallySigned signature;
  if (Deserializer::DeserializeDigitallySigned(jsignature.FromBase64(),
                                               &signature) != Deserializer::OK)
    return done(AsyncLogClient::BAD_RESPONSE);

  sct->Clear();
  sct->set_version(ct::V1);
  sct->mutable_id()->set_key_id(id.FromBase64());
  sct->set_timestamp(timestamp.Value());
  sct->set_extensions(extensions.FromBase64());
  sct->mutable_signature()->CopyFrom(signature);

  return done(AsyncLogClient::OK);
}


}  // namespace

namespace cert_trans {


AsyncLogClient::AsyncLogClient(const shared_ptr<libevent::Base>& base,
                               const string& server_uri)
    : base_(base),
      server_uri_(CHECK_NOTNULL(evhttp_uri_parse(server_uri.c_str())),
                  evhttp_uri_free),
      conn_(base_, server_uri_.get()) {
  const char* const path(evhttp_uri_get_path(server_uri_.get()));
  string newpath;

  if (path)
    newpath.assign(path);

  if (newpath.empty() || newpath.at(newpath.size() - 1) != '/')
    newpath.append("/");

  newpath.append("ct/v1/");

  CHECK_EQ(evhttp_uri_set_path(server_uri_.get(), newpath.c_str()), 0);
}


void AsyncLogClient::GetSTH(SignedTreeHead* sth, const Callback& done) {
  libevent::HttpRequest* const req(
      new libevent::HttpRequest(bind(&DoneGetSTH, _1, sth, done)));

  evhttp_add_header(evhttp_request_get_output_headers(req->get()), "Host",
                    evhttp_uri_get_host(server_uri_.get()));

  conn_.MakeRequest(req, EVHTTP_REQ_GET, GetPath("get-sth"));
}


void AsyncLogClient::GetRoots(vector<shared_ptr<Cert> >* roots,
                              const Callback& done) {
  libevent::HttpRequest* const req(
      new libevent::HttpRequest(bind(&DoneGetRoots, _1, roots, done)));

  evhttp_add_header(evhttp_request_get_output_headers(req->get()), "Host",
                    evhttp_uri_get_host(server_uri_.get()));

  conn_.MakeRequest(req, EVHTTP_REQ_GET, GetPath("get-roots"));
}


void AsyncLogClient::GetEntries(int first, int last,
                                vector<AsyncLogClient::Entry>* entries,
                                const Callback& done) {
  libevent::HttpRequest* const req(
      new libevent::HttpRequest(bind(&DoneGetEntries, _1, entries, done)));

  evhttp_add_header(evhttp_request_get_output_headers(req->get()), "Host",
                    evhttp_uri_get_host(server_uri_.get()));

  ostringstream subpath;
  subpath << "get-entries?start=" << first << "&end=" << last;

  conn_.MakeRequest(req, EVHTTP_REQ_GET, GetPath(subpath.str()));
}


void AsyncLogClient::QueryInclusionProof(const SignedTreeHead& sth,
                                         const std::string& merkle_leaf_hash,
                                         MerkleAuditProof* proof,
                                         const Callback& done) {
  libevent::HttpRequest* const req(new libevent::HttpRequest(
      bind(&DoneQueryInclusionProof, _1, sth, proof, done)));

  evhttp_add_header(evhttp_request_get_output_headers(req->get()), "Host",
                    evhttp_uri_get_host(server_uri_.get()));

  ostringstream subpath;
  subpath << "get-proof-by-hash?hash="
          << UriEncode(util::ToBase64(merkle_leaf_hash))
          << "&tree_size=" << sth.tree_size();

  conn_.MakeRequest(req, EVHTTP_REQ_GET, GetPath(subpath.str()));
}


void AsyncLogClient::GetSTHConsistency(uint64_t first, uint64_t second,
                                       vector<string>* proof,
                                       const Callback& done) {
  libevent::HttpRequest* const req(new libevent::HttpRequest(
      bind(&DoneGetSTHConsistency, _1, proof, done)));

  evhttp_add_header(evhttp_request_get_output_headers(req->get()), "Host",
                    evhttp_uri_get_host(server_uri_.get()));

  ostringstream subpath;
  subpath << "get-sth-consistency?first=" << first << "&second=" << second;

  conn_.MakeRequest(req, EVHTTP_REQ_GET, GetPath(subpath.str()));
}


void AsyncLogClient::AddCertChain(const CertChain& cert_chain,
                                  SignedCertificateTimestamp* sct,
                                  const Callback& done) {
  InternalAddChain(cert_chain, sct, false, done);
}


void AsyncLogClient::AddPreCertChain(const PreCertChain& pre_cert_chain,
                                     SignedCertificateTimestamp* sct,
                                     const Callback& done) {
  InternalAddChain(pre_cert_chain, sct, true, done);
}


string AsyncLogClient::GetPath(const string& subpath) const {
  return CHECK_NOTNULL(evhttp_uri_get_path(server_uri_.get())) + subpath;
}


void AsyncLogClient::InternalAddChain(const CertChain& cert_chain,
                                      SignedCertificateTimestamp* sct,
                                      bool pre_cert, const Callback& done) {
  if (!cert_chain.IsLoaded())
    return done(INVALID_INPUT);

  JsonArray jchain;
  for (size_t n = 0; n < cert_chain.Length(); ++n) {
    string cert;
    CHECK_EQ(Cert::TRUE, cert_chain.CertAt(n)->DerEncoding(&cert));
    jchain.AddBase64(cert);
  }

  JsonObject jsend;
  jsend.Add("chain", jchain);

  libevent::HttpRequest* const req(
      new libevent::HttpRequest(bind(&DoneInternalAddChain, _1, sct, done)));

  evhttp_add_header(evhttp_request_get_output_headers(req->get()), "Host",
                    evhttp_uri_get_host(server_uri_.get()));

  const string json_body(jsend.ToString());
  CHECK_EQ(evbuffer_add(evhttp_request_get_output_buffer(req->get()),
                        json_body.data(), json_body.size()),
           0);

  conn_.MakeRequest(req, EVHTTP_REQ_POST,
                    GetPath(pre_cert ? "add-pre-chain" : "add-chain"));
}


}  // namespace cert_trans
