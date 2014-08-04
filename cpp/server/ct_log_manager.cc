#include "server/ct_log_manager.h"

#include <glog/logging.h>
#include <sstream>

#include "log/database.h"
#include "log/frontend.h"
#include "log/log_lookup.h"
#include "log/tree_signer.h"

using cert_trans::CTLogManager;
using std::multimap;
using std::string;
using std::stringstream;

static const int kCtimeBufSize = 26;


CTLogManager::CTLogManager(Frontend *frontend,
                           TreeSigner<ct::LoggedCertificate> *signer,
                           LogLookup<ct::LoggedCertificate> *lookup)
    : frontend_(frontend),
      signer_(signer),
      lookup_(lookup) {
  LOG(INFO) << "Starting CT log manager";
  time_t last_update = static_cast<time_t>(signer_->LastUpdateTime() / 1000);
  if (last_update > 0) {
    char buf[kCtimeBufSize];
    LOG(INFO) << "Last tree update was at " << ctime_r(&last_update, buf);
  }
}


string CTLogManager::FrontendStats() const {
  Frontend::FrontendStats stats;
  frontend_->GetStats(&stats);
  stringstream ss;
  ss << "Accepted X509 certificates: "
     << stats.x509_accepted << std::endl;
  ss << "Duplicate X509 certificates: "
     << stats.x509_duplicates << std::endl;
  ss << "Bad PEM X509 certificates: "
     << stats.x509_bad_pem_certs << std::endl;
  ss << "Too long X509 certificates: "
     << stats.x509_too_long_certs << std::endl;
  ss << "X509 verify errors: "
     << stats.x509_verify_errors << std::endl;
  ss << "Accepted precertificates: "
     << stats.precert_accepted << std::endl;
  ss << "Duplicate precertificates: "
     << stats.precert_duplicates << std::endl;
  ss << "Bad PEM precertificates: "
     << stats.precert_bad_pem_certs << std::endl;
  ss << "Too long precertificates: "
     << stats.precert_too_long_certs << std::endl;
  ss << "Precertificate verify errors: "
     << stats.precert_verify_errors << std::endl;
  ss << "Badly formatted precertificates: "
     << stats.precert_format_errors << std::endl;
  ss << "Internal errors: "
     << stats.internal_errors << std::endl;
  return ss.str();
}


CTLogManager::LogReply CTLogManager::SubmitEntry(
    ct::CertChain *chain, ct::PreCertChain *prechain,
    ct::SignedCertificateTimestamp *sct, string *error) const {
  CHECK(chain != NULL || prechain != NULL);
  CHECK(!(chain != NULL && prechain != NULL));

  ct::SignedCertificateTimestamp local_sct;
  SubmitResult submit_result = chain != NULL ?
      frontend_->QueueX509Entry(chain, &local_sct)
      : frontend_->QueuePreCertEntry(prechain, &local_sct);

  LogReply reply = REJECT;
  switch (submit_result) {
    case ADDED:
    case DUPLICATE:
      sct->CopyFrom(local_sct);
      reply = SIGNED_CERTIFICATE_TIMESTAMP;
      break;
    default:
      error->assign(Frontend::SubmitResultString(submit_result));
      break;
  }
  return reply;
}


CTLogManager::LookupReply CTLogManager::QueryAuditProof(
    const string& merkle_leaf_hash, size_t tree_size,
    ct::ShortMerkleAuditProof *proof) const {
  ct::ShortMerkleAuditProof local_proof;
  LogLookup<ct::LoggedCertificate>::LookupResult res =
      lookup_->AuditProof(merkle_leaf_hash, tree_size, &local_proof);
  if (res == LogLookup<ct::LoggedCertificate>::OK) {
    proof->CopyFrom(local_proof);
    return MERKLE_AUDIT_PROOF;
  }
  CHECK_EQ(LogLookup<ct::LoggedCertificate>::NOT_FOUND, res);
  return NOT_FOUND;
}


bool CTLogManager::SignMerkleTree() const {
  TreeSigner<ct::LoggedCertificate>::UpdateResult res = signer_->UpdateTree();
  if (res != TreeSigner<ct::LoggedCertificate>::OK) {
    LOG(ERROR) << "Tree update failed with return code " << res;
    return false;
  }
  time_t last_update = static_cast<time_t>(signer_->LastUpdateTime() / 1000);
  {
    char buf[kCtimeBufSize];
    LOG(INFO) << "Tree successfully updated at " << ctime_r(&last_update, buf);
  }
  CHECK_EQ(LogLookup<ct::LoggedCertificate>::UPDATE_OK, lookup_->Update());
  return true;
}


CTLogManager::LookupReply CTLogManager::GetEntry(
    size_t index, ct::LoggedCertificate *result) const {
  if (lookup_->GetEntry(index, result) == LogLookup<ct::LoggedCertificate>::OK)
    return FOUND;
  return NOT_FOUND;
}


const ct::SignedTreeHead CTLogManager::GetSTH() const {
  return signer_->LatestSTH();
}


std::vector<string> CTLogManager::GetConsistency(size_t first,
                                                 size_t second) const {
  return lookup_->ConsistencyProof(first, second);
}


const multimap<string, const ct::Cert*>& CTLogManager::GetRoots() const {
  return frontend_->GetRoots();
}
