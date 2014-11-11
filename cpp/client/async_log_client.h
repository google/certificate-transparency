#ifndef CERT_TRANS_CLIENT_ASYNC_LOG_CLIENT_H_
#define CERT_TRANS_CLIENT_ASYNC_LOG_CLIENT_H_

#include <functional>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

#include "base/macros.h"
#include "proto/ct.pb.h"
#include "util/libevent_wrapper.h"

namespace cert_trans {


class Cert;
class CertChain;
class PreCertChain;


class AsyncLogClient {
 public:
  enum Status {
    OK,
    CONNECT_FAILED,
    BAD_RESPONSE,
    INTERNAL_ERROR,
    UNKNOWN_ERROR,
    UPLOAD_FAILED,
    INVALID_INPUT,
  };

  struct Entry {
    ct::MerkleTreeLeaf leaf;
    ct::LogEntry entry;
  };

  typedef std::function<void(Status)> Callback;

  AsyncLogClient(const std::shared_ptr<libevent::Base>& base,
                 const std::string& server_uri);

  void GetSTH(ct::SignedTreeHead* sth, const Callback& done);

  // This does not clear "roots" before appending to it.
  void GetRoots(std::vector<std::shared_ptr<Cert> >* roots,
                const Callback& done);

  // This does not clear "entries" before appending the retrieved
  // entries.
  void GetEntries(int first, int last, std::vector<Entry>* entries,
                  const Callback& done);

  void QueryInclusionProof(const ct::SignedTreeHead& sth,
                           const std::string& merkle_leaf_hash,
                           ct::MerkleAuditProof* proof, const Callback& done);

  // This does not clear "proof" before appending to it.
  void GetSTHConsistency(uint64_t first, uint64_t second,
                         std::vector<std::string>* proof,
                         const Callback& done);

  // Note: these methods can call "done" inline (before they return),
  // if there is a problem with the (pre-)certificate chain.
  void AddCertChain(const CertChain& cert_chain,
                    ct::SignedCertificateTimestamp* sct, const Callback& done);
  void AddPreCertChain(const PreCertChain& pre_cert_chain,
                       ct::SignedCertificateTimestamp* sct,
                       const Callback& done);

 private:
  std::string GetPath(const std::string& subpath) const;

  void InternalAddChain(const CertChain& cert_chain,
                        ct::SignedCertificateTimestamp* sct, bool pre_cert,
                        const Callback& done);

  const std::shared_ptr<libevent::Base> base_;
  const std::shared_ptr<evhttp_uri> server_uri_;
  const std::shared_ptr<libevent::HttpConnection> conn_;

  DISALLOW_COPY_AND_ASSIGN(AsyncLogClient);
};


}  // namespace cert_trans


#endif  // CERT_TRANS_CLIENT_ASYNC_LOG_CLIENT_H_
