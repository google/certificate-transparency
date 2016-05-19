#ifndef CERT_TRANS_CLIENT_HTTP_LOG_CLIENT_H_
#define CERT_TRANS_CLIENT_HTTP_LOG_CLIENT_H_

#include <stdint.h>
#include <memory>
#include <string>

#include "base/macros.h"
#include "client/async_log_client.h"
#include "proto/ct.pb.h"
#include "util/libevent_wrapper.h"
#include "util/statusor.h"
#include "util/thread_pool.h"

namespace cert_trans {

class Cert;


class HTTPLogClient {
 public:
  explicit HTTPLogClient(const std::string& server);

  util::StatusOr<ct::SignedCertificateTimestamp> UploadSubmission(
      const std::string& submission, bool pre);

  util::StatusOr<ct::SignedTreeHead> GetSTH();

  util::StatusOr<std::vector<std::unique_ptr<Cert>>> GetRoots();

  util::StatusOr<ct::MerkleAuditProof> QueryAuditProof(
      const std::string& merkle_leaf_hash);

  util::StatusOr<std::vector<std::string>> GetSTHConsistency(int64_t size1,
                                                             int64_t size2);

  util::StatusOr<std::vector<AsyncLogClient::Entry>> GetEntries(int first,
                                                                int last);

 private:
  const std::unique_ptr<libevent::Base> base_;
  ThreadPool pool_;
  UrlFetcher fetcher_;
  AsyncLogClient client_;

  DISALLOW_COPY_AND_ASSIGN(HTTPLogClient);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_CLIENT_HTTP_LOG_CLIENT_H_
