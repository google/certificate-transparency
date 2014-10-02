/* -*- indent-tabs-mode: nil -*- */
#include "client/http_log_client.h"

#include <boost/bind.hpp>
#include <boost/make_shared.hpp>
#include <event2/buffer.h>
#include <glog/logging.h>
#include <sstream>

#include "log/cert.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"
#include "util/json_wrapper.h"
#include "util/util.h"

namespace libevent = cert_trans::libevent;

using boost::bind;
using boost::make_shared;
using boost::shared_ptr;
using ct::Cert;
using ct::CertChain;
using ct::SignedCertificateTimestamp;
using std::ostringstream;
using std::string;
using std::vector;

namespace {


class HttpRequest {
 public:
  static string UrlEscape(const string &input) {
    // TODO(pphaneuf): I just wanted the deleter, so std::unique_ptr
    // would have worked, but it's not available to us (C++11).
    const shared_ptr<char> output(
        evhttp_uriencode(input.data(), input.size(), false), free);

    return output.get();
  }

  HttpRequest(const shared_ptr<libevent::Base> &base,
              libevent::HttpConnection *conn, evhttp_uri *server,
              const string &subpath)
      : base_(base),
        conn_(CHECK_NOTNULL(conn)),
        path_(CHECK_NOTNULL(evhttp_uri_get_path(server)) + subpath),
        req_(bind(&HttpRequest::Done, this, _1)),
        request_sent_(false),
        done_(false),
        response_code_(-1),
        response_body_(CHECK_NOTNULL(evbuffer_new()), evbuffer_free) {
    evhttp_add_header(evhttp_request_get_output_headers(req_.get()), "Host",
                      evhttp_uri_get_host(server));
  }

  void SetPostBody(const string &post_body) {
    const shared_ptr<evbuffer> body(
        CHECK_NOTNULL(evbuffer_new()), evbuffer_free);

    CHECK_EQ(evbuffer_add(body.get(), post_body.data(), post_body.size()), 0);

    request_body_ = body;
  }

  // Returns HTTP response code, or zero if there was an error before
  // getting the HTTP response.
  HTTPLogClient::Status Run() {
    evhttp_cmd_type req_type(EVHTTP_REQ_GET);

    if (request_body_) {
      evbuffer_add_buffer(
          CHECK_NOTNULL(evhttp_request_get_output_buffer(req_.get())),
          request_body_.get());
      req_type = EVHTTP_REQ_POST;
    }

    conn_->MakeRequest(&req_, req_type, path_.c_str());
    request_sent_ = true;

    while (!done_) {
      base_->DispatchOnce();
    }

    switch (response_code_) {
      case HTTP_OK:
        return HTTPLogClient::OK;

      case 0:
        return HTTPLogClient::CONNECT_FAILED;

      default:
        LOG(ERROR) << "unexpected response code: " << response_code_;
    }

    return HTTPLogClient::UNKNOWN_ERROR;
  }

  evbuffer *GetResponseBody() {
    return response_body_.get();
  }

 private:
  void Done(libevent::HttpRequest *req) {
    response_code_ = evhttp_request_get_response_code(req->get());
    if (evhttp_request_get_input_buffer(req->get())) {
      evbuffer_add_buffer(response_body_.get(),
                          evhttp_request_get_input_buffer(req->get()));
    }

    done_ = true;
  }

  const shared_ptr<libevent::Base> base_;
  libevent::HttpConnection *const conn_;
  const string path_;
  libevent::HttpRequest req_;
  shared_ptr<evbuffer> request_body_;
  bool request_sent_;

  bool done_;
  int response_code_;
  // TODO(pphaneuf): I just wanted the deleter, so std::unique_ptr
  // would have worked, but it's not available to us (C++11).
  const shared_ptr<evbuffer> response_body_;

  DISALLOW_COPY_AND_ASSIGN(HttpRequest);
};


}  // namespace

HTTPLogClient::HTTPLogClient(const string &server)
    : server_(CHECK_NOTNULL(evhttp_uri_parse(server.c_str()))),
      base_(make_shared<libevent::Base>()),
      conn_(base_, server_) {
  const char *const path(evhttp_uri_get_path(server_));
  string newpath;

  if (path)
    newpath = path;

  if (newpath.empty() || newpath.at(newpath.size() - 1) != '/')
    newpath.append("/");

  newpath.append("ct/v1/");

  CHECK_EQ(evhttp_uri_set_path(server_, newpath.c_str()), 0);
}

HTTPLogClient::~HTTPLogClient() {
  evhttp_uri_free(server_);
}


HTTPLogClient::Status
HTTPLogClient::UploadSubmission(const string &submission, bool pre,
                                SignedCertificateTimestamp *sct) {

  CertChain chain(submission);

  if (!chain.IsLoaded())
    return INVALID_INPUT;

  JsonArray jchain;
  for (size_t n = 0; n < chain.Length(); ++n) {
    string cert;
    CHECK_EQ(Cert::TRUE, chain.CertAt(n)->DerEncoding(&cert));
    jchain.Add(util::ToBase64(cert));
  }

  JsonObject jsend;
  jsend.Add("chain", jchain);

  const string jsoned(jsend.ToString());

  HttpRequest request(base_, &conn_, server_,
                      pre ? "add-pre-chain" : "add-chain");
  request.SetPostBody(jsoned);

  Status ret(request.Run());
  if (ret != OK)
    return ret;

  JsonObject jresponse(request.GetResponseBody());
  if (!jresponse.Ok()) {
    // TODO(pphaneuf): Would be nice if we could easily output the
    // response here.
    LOG(ERROR) << "Could not parse response";
    return BAD_RESPONSE;
  }

  if (!jresponse.IsType(json_type_object)) {
    LOG(ERROR) << "Expected a JSON object, got: " << jresponse.ToString();
    return BAD_RESPONSE;
  }

  JsonString id(jresponse, "id");
  if (!id.Ok())
    return BAD_RESPONSE;
  sct->mutable_id()->set_key_id(id.FromBase64());

  JsonInt timestamp(jresponse, "timestamp");
  if (!timestamp.Ok())
    return BAD_RESPONSE;
  sct->set_timestamp(timestamp.Value());

  JsonString extensions(jresponse, "extensions");
  if (!extensions.Ok())
    return BAD_RESPONSE;
  sct->set_extensions(extensions.FromBase64());

  JsonString signature(jresponse, "signature");
  if (!signature.Ok())
    return BAD_RESPONSE;
  if (Deserializer::DeserializeDigitallySigned(signature.FromBase64(),
                                               sct->mutable_signature())
      != Deserializer::OK)
    return BAD_RESPONSE;

  sct->set_version(ct::V1);

  return OK;
}


HTTPLogClient::Status HTTPLogClient::GetSTH(ct::SignedTreeHead *sth) {
  HttpRequest request(base_, &conn_, server_, "get-sth");

  Status ret(request.Run());
  if (ret != OK)
    return ret;

  JsonObject jresponse(request.GetResponseBody());
  if (!jresponse.Ok())
    return BAD_RESPONSE;

  JsonInt tree_size(jresponse, "tree_size");
  if (!tree_size.Ok())
    return BAD_RESPONSE;
  sth->set_tree_size(tree_size.Value());

  JsonInt timestamp(jresponse, "timestamp");
  if (!timestamp.Ok())
    return BAD_RESPONSE;
  sth->set_timestamp(timestamp.Value());

  JsonString root_hash(jresponse, "sha256_root_hash");
  if (!root_hash.Ok())
    return BAD_RESPONSE;
  sth->set_sha256_root_hash(root_hash.FromBase64());

  JsonString signature(jresponse, "tree_head_signature");
  if (!signature.Ok())
    return BAD_RESPONSE;
  if (Deserializer::DeserializeDigitallySigned(signature.FromBase64(),
                                               sth->mutable_signature())
      != Deserializer::OK)
    return BAD_RESPONSE;

  sth->set_version(ct::V1);

  return OK;
}

HTTPLogClient::Status HTTPLogClient::GetRoots(
    vector<shared_ptr<Cert> > *roots) {
  HttpRequest request(base_, &conn_, server_, "get-roots");

  Status ret(request.Run());
  if (ret != OK)
    return ret;

  JsonObject jresponse(request.GetResponseBody());
  if (!jresponse.Ok())
    return BAD_RESPONSE;

  JsonArray jroots(jresponse, "certificates");
  if (!jroots.Ok())
    return BAD_RESPONSE;

  vector<shared_ptr<Cert> > retval;
  for (int i = 0; i < jroots.Length(); ++i) {
    JsonString jcert(jroots, i);
    if (!jcert.Ok())
      return BAD_RESPONSE;

    shared_ptr<Cert> cert(make_shared<Cert>());
    const Cert::Status status(cert->LoadFromDerString(jcert.FromBase64()));
    if (status != Cert::TRUE)
      return BAD_RESPONSE;

    retval.push_back(cert);
  }

  roots->swap(retval);

  return OK;
}

HTTPLogClient::Status
HTTPLogClient::QueryAuditProof(const string &merkle_leaf_hash,
                               ct::MerkleAuditProof *proof) {
  HttpRequest request(base_, &conn_, server_, "get-sth");

  Status ret(request.Run());
  if (ret != OK)
    return ret;

  JsonObject jresponse(request.GetResponseBody());

  JsonInt tree_size(jresponse, "tree_size");
  if (!tree_size.Ok())
    return BAD_RESPONSE;
  proof->set_tree_size(tree_size.Value());

  JsonInt timestamp(jresponse, "timestamp");
  if (!timestamp.Ok())
    return BAD_RESPONSE;
  proof->set_timestamp(timestamp.Value());

  JsonString signature(jresponse, "tree_head_signature");
  if (!signature.Ok())
    return BAD_RESPONSE;
  if (Deserializer::DeserializeDigitallySigned(signature.FromBase64(),
          proof->mutable_tree_head_signature()) != Deserializer::OK)
    return BAD_RESPONSE;

  ostringstream path;
  path << "get-proof-by-hash?hash="
       << HttpRequest::UrlEscape(util::ToBase64(merkle_leaf_hash))
       << "&tree_size=" << tree_size.Value();
  HttpRequest request2(base_, &conn_, server_, path.str());

  ret = request2.Run();
  if (ret != OK)
    return ret;

  JsonObject jresponse2(request2.GetResponseBody());
  if (!jresponse2.Ok())
    return BAD_RESPONSE;

  JsonInt leaf_index(jresponse2, "leaf_index");
  if (!leaf_index.Ok())
    return BAD_RESPONSE;
  proof->set_leaf_index(leaf_index.Value());

  JsonArray audit_path(jresponse2, "audit_path");
  if (!audit_path.Ok())
    return BAD_RESPONSE;

  for (int n = 0; n < audit_path.Length(); ++n) {
    JsonString path_node(audit_path, n);
    CHECK(path_node.Ok());
    proof->add_path_node(path_node.FromBase64());
  }

  proof->set_version(ct::V1);

  return OK;
}

HTTPLogClient::Status HTTPLogClient::GetEntries(int first, int last,
                                                vector<LogEntry> *entries) {
  ostringstream path;
  path << "get-entries?start=" << first << "&end=" << last;
  HttpRequest request(base_, &conn_, server_, path.str());

  Status ret(request.Run());
  if (ret != OK)
    return ret;

  JsonObject jresponse(request.GetResponseBody());
  if (!jresponse.Ok())
    return BAD_RESPONSE;

  JsonArray jentries(jresponse, "entries");
  if (!jentries.Ok())
    return BAD_RESPONSE;

  for (int n = 0; n < jentries.Length(); ++n) {
    JsonObject entry(jentries, n);
    if (!entry.Ok())
      return BAD_RESPONSE;

    JsonString leaf_input(entry, "leaf_input");
    if (!leaf_input.Ok())
      return BAD_RESPONSE;

    LogEntry log_entry;
    if (Deserializer::DeserializeMerkleTreeLeaf(leaf_input.FromBase64(),
                                                &log_entry.leaf)
        != Deserializer::OK)
      return BAD_RESPONSE;

    JsonString extra_data(entry, "extra_data");
    if (!extra_data.Ok())
      return BAD_RESPONSE;

    if (log_entry.leaf.timestamped_entry().entry_type() == ct::X509_ENTRY)
      Deserializer::DeserializeX509Chain(extra_data.FromBase64(),
                                         log_entry.entry.mutable_x509_entry());
    else if (log_entry.leaf.timestamped_entry().entry_type()
            == ct::PRECERT_ENTRY)
      Deserializer::DeserializePrecertChainEntry(extra_data.FromBase64(),
          log_entry.entry.mutable_precert_entry());
    else
      LOG(FATAL) << "Don't understand entry type: "
                 << log_entry.leaf.timestamped_entry().entry_type();

    entries->push_back(log_entry);
  }

  return OK;
}

HTTPLogClient::Status
HTTPLogClient::GetSTHConsistency(uint64_t size1, uint64_t size2,
                                 vector<string> *proof) {
  ostringstream path;
  path << "get-sth-consistency?first=" << size1 << "&second=" << size2;
  HttpRequest request(base_, &conn_, server_, path.str());

  Status ret(request.Run());
  if (ret != OK)
    return ret;

  JsonObject jresponse(request.GetResponseBody());
  if (!jresponse.Ok())
    return BAD_RESPONSE;

  JsonArray jproof(jresponse, "consistency");
  if (!jproof.Ok())
    return BAD_RESPONSE;

  for (int n = 0; n < jproof.Length(); ++n) {
    JsonString entry(jproof, n);
    if (!entry.Ok())
      return BAD_RESPONSE;

    proof->push_back(entry.FromBase64());
  }

  return OK;
}
