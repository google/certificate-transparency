#ifndef CERT_TRANS_SERVER_CT_LOG_MANAGER_H_
#define CERT_TRANS_SERVER_CT_LOG_MANAGER_H_

#include <boost/scoped_ptr.hpp>
#include <map>
#include <string>
#include <vector>

#include "base/macros.h"
#include "proto/ct.pb.h"

class Frontend;
template <class T> class LogLookup;
template <class T> class TreeSigner;

namespace ct {
class Cert;
class CertChain;
class LoggedCertificate;
class PreCertChain;
}

namespace cert_trans {


class CTLogManager {
 public:
  enum LogReply {
    SIGNED_CERTIFICATE_TIMESTAMP,
    REJECT,
  };

  enum LookupReply {
    MERKLE_AUDIT_PROOF,
    NOT_FOUND,
    FOUND,
  };

  CTLogManager(Frontend *frontend,
               TreeSigner<ct::LoggedCertificate> *signer,
               LogLookup<ct::LoggedCertificate> *lookup);

  std::string FrontendStats() const;

  LogReply SubmitEntry(ct::CertChain *chain, ct::PreCertChain *prechain,
                       ct::SignedCertificateTimestamp *sct,
                       std::string *error) const;

  LookupReply QueryAuditProof(const std::string &merkle_leaf_hash,
                              size_t tree_size,
                              ct::ShortMerkleAuditProof *proof) const;

  void SignMerkleTree() const;

  LookupReply GetEntry(size_t index, ct::LoggedCertificate *result) const;

  const ct::SignedTreeHead GetSTH() const;

  std::vector<std::string> GetConsistency(size_t first, size_t second) const;

  const std::multimap<std::string, const ct::Cert*>& GetRoots() const;

 private:
  const boost::scoped_ptr<Frontend> frontend_;
  const boost::scoped_ptr<TreeSigner<ct::LoggedCertificate> > signer_;
  const boost::scoped_ptr<LogLookup<ct::LoggedCertificate> > lookup_;

  DISALLOW_COPY_AND_ASSIGN(CTLogManager);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_SERVER_CT_LOG_MANAGER_H_
