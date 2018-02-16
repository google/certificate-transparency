#ifndef CERT_TRANS_LOG_CERT_SUBMISSION_HANDLER_H_
#define CERT_TRANS_LOG_CERT_SUBMISSION_HANDLER_H_

#include <string>
#include <vector>

#include "log/cert_checker.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"
#include "util/status.h"

namespace cert_trans {


// Parse incoming submissions, do preliminary sanity checks and pass them
// through cert checker.
// Prepare for signing by parsing the input into an appropriate
// log entry structure.
class CertSubmissionHandler {
 public:
  // Does not take ownership of the cert_checker.
  explicit CertSubmissionHandler(const cert_trans::CertChecker* cert_checker);
  CertSubmissionHandler(const CertSubmissionHandler&) = delete;
  CertSubmissionHandler& operator=(const CertSubmissionHandler&) = delete;

  // These may change |chain|.
  // TODO(pphaneuf): These could return StatusOr<ct::LogEntry>.
  util::Status ProcessX509Submission(cert_trans::CertChain* chain,
                                     ct::LogEntry* entry) const;
  util::Status ProcessPreCertSubmission(cert_trans::PreCertChain* chain,
                                        ct::LogEntry* entry) const;

  // For clients, to reconstruct all possible bytestrings under the signature
  // from the observed chain. Does not check whether the entry has valid format
  // (i.e., does not check length limits).
  static util::Status X509ChainToEntries(
      const cert_trans::CertChain& chain,
      ct::LogEntry *x509_entry,
      std::vector<ct::LogEntry>* precert_entries);

  // Deprecated version, please use X509ChainToEntries.
  // Same as X509ChainToEntries, but does not support log entries that are
  // signed by a special-purpose certificate (the 1st option in RFC6962,
  // section 3.1) nor certificates with embedded SCTs that were again
  // submitted to a certificate log in order to get new SCTs that can be
  // sent in a TLS handshake extension or in a stapled OCSP response.
  static bool X509ChainToEntry(const cert_trans::CertChain& chain,
                               ct::LogEntry* entry);

 private:
  const cert_trans::CertChecker* const cert_checker_;
};


}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_CERT_SUBMISSION_HANDLER_H_
