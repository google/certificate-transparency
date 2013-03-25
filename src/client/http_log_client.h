/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef HTTP_LOG_CLIENT_H
#define HTTP_LOG_CLIENT_H

#include "proto/ct.pb.h"

#include <stdint.h>

#include <string>

namespace ct {
class MerkleAuditProof;
class SignedCertificateTimestamp;
};

class HTTPLogClient {
 public:
  HTTPLogClient(const std::string &server, uint16_t port) : server_(server),
                                                            port_(port) {}

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

  Status QueryAuditProof(const std::string &merkle_leaf_hash,
                         ct::MerkleAuditProof *proof);

  struct LogEntry {
    ct::MerkleTreeLeaf leaf;
    ct::LogEntry entry;
  };

  // This does not clear |entries| before appending the retrieved
  // entries.
  Status GetEntries(int first, int last, std::vector<LogEntry> *entries);

private:
  void BaseUrl(std::ostringstream *url);

  std::string server_;
  uint16_t port_;
};

#endif
