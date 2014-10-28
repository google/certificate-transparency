/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef HTTP_LOG_CLIENT_H
#define HTTP_LOG_CLIENT_H

#include <memory>
#include <stdint.h>
#include <string>

#include "base/macros.h"
#include "client/async_log_client.h"
#include "proto/ct.pb.h"
#include "util/libevent_wrapper.h"

namespace cert_trans {

class Cert;


class HTTPLogClient {
 public:
  explicit HTTPLogClient(const std::string& server);

  AsyncLogClient::Status UploadSubmission(const std::string& submission,
                                          bool pre,
                                          ct::SignedCertificateTimestamp* sct);

  AsyncLogClient::Status GetSTH(ct::SignedTreeHead* sth);

  AsyncLogClient::Status GetRoots(
      std::vector<std::shared_ptr<Cert> >* roots);

  AsyncLogClient::Status QueryAuditProof(const std::string& merkle_leaf_hash,
                                         ct::MerkleAuditProof* proof);

  AsyncLogClient::Status GetSTHConsistency(uint64_t size1, uint64_t size2,
                                           std::vector<std::string>* proof);

  // This does not clear |entries| before appending the retrieved
  // entries.
  AsyncLogClient::Status GetEntries(
      int first, int last, std::vector<AsyncLogClient::Entry>* entries);

 private:
  const std::shared_ptr<libevent::Base> base_;
  AsyncLogClient client_;

  DISALLOW_COPY_AND_ASSIGN(HTTPLogClient);
};


}  // namespace cert_trans

#endif
