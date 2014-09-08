/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef HTTP_LOG_CLIENT_H
#define HTTP_LOG_CLIENT_H

#include "proto/ct.pb.h"

#include <boost/shared_ptr.hpp>
#include <stdint.h>

#include <string>

namespace ct {
class Cert;
class MerkleAuditProof;
class SignedCertificateTimestamp;
};

class HTTPLogClient {
 public:
  HTTPLogClient(const std::string &server) : server_(server) {}

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
                          ct::SignedCertificateTimestamp *sct) const;

  Status GetSTH(ct::SignedTreeHead *sth) const;

  Status GetRoots(std::vector<boost::shared_ptr<ct::Cert> > *roots) const;

  Status QueryAuditProof(const std::string &merkle_leaf_hash,
                         ct::MerkleAuditProof *proof) const;

  Status GetSTHConsistency(uint64_t size1, uint64_t size2,
                           std::vector<std::string> *proof) const;

  struct LogEntry {
    ct::MerkleTreeLeaf leaf;
    ct::LogEntry entry;
  };

  // This does not clear |entries| before appending the retrieved
  // entries.
  Status GetEntries(int first, int last, std::vector<LogEntry> *entries) const;

private:
  void BaseUrl(std::ostringstream *url) const;

  std::string server_;
};

#endif
