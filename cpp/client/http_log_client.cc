/* -*- indent-tabs-mode: nil -*- */
#include "client/http_log_client.h"

#include <curl/curl.h>
#include <glog/logging.h>
#include <sstream>

#include "log/cert.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"
#include "util/json_wrapper.h"
#include "util/util.h"

using ct::Cert;
using ct::CertChain;
using std::ostringstream;
using std::string;

namespace {


class CurlRequest {
 public:
  CurlRequest()
      : handle_(CHECK_NOTNULL(curl_easy_init())) {
  }
  ~CurlRequest() {
    curl_easy_cleanup(handle_);
  }

  void SetUrl(const std::string& url) {
    CHECK_EQ(curl_easy_setopt(handle_, CURLOPT_URL, url.c_str()), CURLE_OK);
  }

  void SetPostFields(const std::string& post_fields) {
    const long postsize(post_fields.size());
    CHECK_EQ(curl_easy_setopt(
        handle_, CURLOPT_POSTFIELDSIZE, postsize), CURLE_OK);
    CHECK_EQ(curl_easy_setopt(
        handle_, CURLOPT_COPYPOSTFIELDS, post_fields.data()), CURLE_OK);
  }

  std::string UrlEscape(const std::string& url) {
    char* escaped(CHECK_NOTNULL(curl_easy_escape(
        handle_, url.c_str(), url.size())));

    const std::string retval(escaped);
    curl_free(escaped);

    return retval;
  }

  CURLcode Perform(std::ostream* output) {
    curl_easy_setopt(handle_, CURLOPT_WRITEFUNCTION,
                     &CurlRequest::write_callback);
    curl_easy_setopt(handle_, CURLOPT_WRITEDATA, output);

    return curl_easy_perform(handle_);
  }

 private:
  CURL* const handle_;

  // Private declarations without definitions, to disallow copying.
  CurlRequest(const CurlRequest&);
  CurlRequest& operator=(const CurlRequest&);

  static size_t write_callback(char* buffer, size_t size, size_t nmemb,
                                    std::ostream* stream) {
    const size_t sumsize(size * nmemb);

    stream->write(buffer, sumsize);
    if (!*stream)
      return 0;

    return sumsize;
  }
};


}  // namespace

void HTTPLogClient::BaseUrl(ostringstream *url) const {
  *url << "http://" << server_ << "/ct/v1/";
}

static HTTPLogClient::Status SendRequest(ostringstream *response,
                                         CurlRequest *request,
                                         const ostringstream &url) {
  request->SetUrl(url.str());

  const CURLcode code(request->Perform(response));
  switch (code) {
    case CURLE_OK:
      return HTTPLogClient::OK;

    case CURLE_COULDNT_CONNECT:
      return HTTPLogClient::CONNECT_FAILED;

    default:
      LOG(ERROR) << "curl error: " << curl_easy_strerror(code);
      return HTTPLogClient::UNKNOWN_ERROR;
  }
}

HTTPLogClient::Status
HTTPLogClient::UploadSubmission(const std::string &submission, bool pre,
                                ct::SignedCertificateTimestamp *sct) const {

  CertChain chain(submission);

  if (!chain.IsLoaded())
    return INVALID_INPUT;

  JsonArray jchain;
  for (size_t n = 0; n < chain.Length(); ++n) {
    string cert;
    CHECK_EQ(Cert::TRUE, chain.CertAt(n)->DerEncoding(&cert));
    jchain.Add(json_object_new_string(util::ToBase64(cert).c_str()));
  }
  json_object *jsend = json_object_new_object();
  json_object_object_add(jsend, "chain", jchain.Extract());

  const char *jsoned = json_object_to_json_string(jsend);

  ostringstream url;
  BaseUrl(&url);
  url << "add-";
  if (pre)
    url << "pre-";
  url << "chain";

  CurlRequest request;
  request.SetPostFields(jsoned);

  std::ostringstream response;
  Status ret = SendRequest(&response, &request, url);
  LOG(INFO) << "request = " << url.str();
  LOG(INFO) << "body = " << jsoned;
  LOG(INFO) << "response = " << response.str();
  json_object_put(jsend);
  if (ret != OK)
    return ret;

  JsonObject jresponse(json_tokener_parse(response.str().c_str()));

  if (!jresponse.IsType(json_type_object)) {
    LOG(ERROR) << "Expected a JSON object, got: " << response.str();
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

HTTPLogClient::Status HTTPLogClient::GetSTH(ct::SignedTreeHead *sth) const {
  ostringstream url;
  BaseUrl(&url);
  url << "get-sth";

  CurlRequest request;

  std::ostringstream response;
  Status ret = SendRequest(&response, &request, url);
  LOG(INFO) << "request = " << url.str();
  LOG(INFO) << "response = " << response.str();
  if (ret != OK)
    return ret;

  JsonObject jresponse(response);

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

HTTPLogClient::Status
HTTPLogClient::QueryAuditProof(const string &merkle_leaf_hash,
                               ct::MerkleAuditProof *proof) const {
  ostringstream url;
  BaseUrl(&url);
  url << "get-sth";

  CurlRequest request;

  std::ostringstream response;
  Status ret = SendRequest(&response, &request, url);
  LOG(INFO) << "request = " << url.str();
  LOG(INFO) << "response = " << response.str();
  if (ret != OK)
    return ret;

  JsonObject jresponse(response);

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

  ostringstream url2;
  CurlRequest request2;
  BaseUrl(&url2);
  url2 << "get-proof-by-hash?hash="
       << request2.UrlEscape(util::ToBase64(merkle_leaf_hash))
       << "&tree_size=" << tree_size.Value();
  std::ostringstream response2;
  ret = SendRequest(&response2, &request2, url2);
  LOG(INFO) << "request = " << url2.str();
  LOG(INFO) << "response = " << response2.str();
  if (ret != OK)
    return ret;

  JsonObject jresponse2(response2);
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
                                               std::vector<LogEntry> *entries)
    const {
  ostringstream url;
  BaseUrl(&url);
  url << "get-entries?start=" << first << "&end=" << last;

  CurlRequest request;

  std::ostringstream response;
  Status ret = SendRequest(&response, &request, url);
  LOG(INFO) << "request = " << url.str();
  LOG(INFO) << "response = " << response.str();
  if (ret != OK)
    return ret;

  JsonObject jresponse(response);
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
                                 std::vector<std::string> *proof) const {
  ostringstream url;
  BaseUrl(&url);
  url << "get-sth-consistency?first=" << size1 << "&second=" << size2;

  CurlRequest request;

  std::ostringstream response;
  Status ret = SendRequest(&response, &request, url);
  LOG(INFO) << "request = " << url.str();
  LOG(INFO) << "response = " << response.str();
  if (ret != OK)
    return ret;

  JsonObject jresponse(response);
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
