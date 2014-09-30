/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef HTTP_LOG_CLIENT_H
#define HTTP_LOG_CLIENT_H

#include <boost/shared_ptr.hpp>
#include <stdint.h>
#include <string>

#include "base/macros.h"
#include "proto/ct.pb.h"
#include "util/libevent_wrapper.h"

namespace ct {
class Cert;
class MerkleAuditProof;
class SignedCertificateTimestamp;
};

class HTTPLogClient {
 public:
  explicit HTTPLogClient(const std::string &server);
  ~HTTPLogClient();

  enum Status {
    OK,
    CONNECT_FAILED,
    BAD_RESPONSE,
    INTERNAL_ERROR,
    UNKNOWN_ERROR,
    UPLOAD_FAILED,
    INVALID_INPUT,
  };

  Status UploadSubmission(const std::string &submission, bool pre,
                          ct::SignedCertificateTimestamp *sct);

  Status GetSTH(ct::SignedTreeHead *sth);

  Status GetRoots(std::vector<boost::shared_ptr<ct::Cert> > *roots);

  Status QueryAuditProof(const std::string &merkle_leaf_hash,
                         ct::MerkleAuditProof *proof);

  Status GetSTHConsistency(uint64_t size1, uint64_t size2,
                           std::vector<std::string> *proof);

  struct LogEntry {
    ct::MerkleTreeLeaf leaf;
    ct::LogEntry entry;
  };

  // This does not clear |entries| before appending the retrieved
  // entries.
  Status GetEntries(int first, int last, std::vector<LogEntry> *entries);

private:
  evhttp_uri *const server_;
  const boost::shared_ptr<cert_trans::libevent::Base> base_;
  cert_trans::libevent::HttpConnection conn_;

  DISALLOW_COPY_AND_ASSIGN(HTTPLogClient);
};

#endif
