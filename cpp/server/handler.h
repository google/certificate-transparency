#ifndef CERT_TRANS_SERVER_HANDLER_H_
#define CERT_TRANS_SERVER_HANDLER_H_

#include <boost/network/protocol/http/server.hpp>
#include <string>

#include "server/ct_log_manager.h"

namespace ct {
class CertChain;
class PreCertChain;
class SignedCertificateTimestamp;
}

namespace cert_trans {

class CTLogManager;


class HttpHandler {
 public:
  typedef boost::network::http::server<HttpHandler> server;

  HttpHandler(CTLogManager *manager) : manager_(manager) {}

  void operator() (server::request const &request,
                   server::response &response);

  void log(const std::string &err);

private:
  static void BadRequest(server::response &response, const char *msg);

  void GetRoots(server::response &response) const;

  void GetEntries(server::response &response,
                  const boost::network::uri::uri &uri) const;

  void GetConsistency(server::response &response,
                      const boost::network::uri::uri &uri);

  void GetProof(server::response &response,
                const boost::network::uri::uri &uri);

  void GetSTH(server::response &response);

  void AddChain(server::response &response, const std::string &body);
  void AddPreChain(server::response &response, const std::string &body);
  void AddChain(server::response &response, const std::string &body,
                ct::CertChain *chain, ct::PreCertChain *prechain);

  static bool ExtractChain(server::response &response, ct::CertChain *chain,
                           const std::string &body);

  void ProcessChainResult(server::response &response,
                          CTLogManager::LogReply result,
                          const std::string &error,
                          const ct::SignedCertificateTimestamp &sct);

  const CTLogManager* manager_;
};


}  // namespace cert_trans

#endif  // CERT_TRANS_SERVER_HANDLER_H_
