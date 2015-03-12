#include "server/json_output.h"

#include <event2/http.h>
#include <glog/logging.h>
#include <string>

#include "util/json_wrapper.h"
#include "util/libevent_wrapper.h"

using std::string;

namespace cert_trans {
namespace {


static const char kJsonContentType[] = "application/json; charset=utf-8";


string LogRequest(evhttp_request* req, int http_status, int resp_body_length) {
  evhttp_connection* conn = evhttp_request_get_connection(req);
  char* peer_addr;
  ev_uint16_t peer_port;
  evhttp_connection_get_peer(conn, &peer_addr, &peer_port);

  string http_verb;
  switch (evhttp_request_get_command(req)) {
    case EVHTTP_REQ_DELETE:
      http_verb = "DELETE";
      break;
    case EVHTTP_REQ_GET:
      http_verb = "GET";
      break;
    case EVHTTP_REQ_HEAD:
      http_verb = "HEAD";
      break;
    case EVHTTP_REQ_POST:
      http_verb = "POST";
      break;
    case EVHTTP_REQ_PUT:
      http_verb = "PUT";
      break;
    default:
      http_verb = "UNKNOWN";
      break;
  }

  const string uri(evhttp_request_get_uri(req));
  return string(peer_addr) + " \"" + http_verb + " " + uri + "\" " +
         std::to_string(http_status) + " " + std::to_string(resp_body_length);
}


}  // namespace


JsonOutput::JsonOutput(libevent::Base* base) : base_(CHECK_NOTNULL(base)) {
}


void JsonOutput::SendJsonReply(evhttp_request* req, int http_status,
                               const JsonObject& json) {
  CHECK_EQ(evhttp_add_header(evhttp_request_get_output_headers(req),
                             "Content-Type", kJsonContentType),
           0);
  const string resp_body(json.ToString());
  CHECK_GT(evbuffer_add_printf(evhttp_request_get_output_buffer(req), "%s",
                               resp_body.c_str()),
           0);

  const string logstr(LogRequest(req, http_status, resp_body.size()));
  const auto send_reply([req, http_status, logstr]() {
    evhttp_send_reply(req, http_status, /*reason*/ NULL, /*databuf*/ NULL);
    LOG(INFO) << logstr;
  });

  if (!libevent::Base::OnEventThread()) {
    base_->Add(send_reply);
  } else {
    send_reply();
  }
}


void JsonOutput::SendError(evhttp_request* req, int http_status,
                           const string& error_msg) {
  JsonObject json_reply;
  json_reply.Add("error_message", error_msg);
  json_reply.AddBoolean("success", false);

  SendJsonReply(req, http_status, json_reply);
}


}  // namespace cert_trans
