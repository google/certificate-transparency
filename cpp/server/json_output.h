#ifndef CERT_TRANS_SERVER_JSON_OUTPUT_H_
#define CERT_TRANS_SERVER_JSON_OUTPUT_H_

#include <string>

#include "base/macros.h"

struct evhttp_request;
class JsonObject;

namespace cert_trans {
namespace libevent {
class Base;
}  // namespace libevent


class JsonOutput {
 public:
  JsonOutput(libevent::Base* base);

  void SendJsonReply(evhttp_request* req, int http_status,
                     const JsonObject& json);


  void SendError(evhttp_request* req, int http_status,
                 const std::string& error_msg);

 private:
  libevent::Base* const base_;

  DISALLOW_COPY_AND_ASSIGN(JsonOutput);
};


}  // namespace cert_trans


#endif  // CERT_TRANS_SERVER_JSON_OUTPUT_H_
