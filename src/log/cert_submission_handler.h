#ifndef CERT_SUBMISSION_HANDLER_H
#define CERT_SUBMISSION_HANDLER_H

#include <string>

#include "cert_checker.h"
#include "ct.pb.h"
#include "submission_handler.h"
#include "types.h"

// Parse incoming submissions, do preliminary sanity checks and pass them
// through cert checker.
// Prepare for signing by parsing the input into an appropriate
// log entry structure.
class CertSubmissionHandler : public SubmissionHandler {
 public:
  // Does not take ownership of the cert_checker.
  CertSubmissionHandler(CertChecker *cert_checker);
  ~CertSubmissionHandler() {}


  // For clients, to reconstruct the bytestring under the signature
  // from the observed chain. Caller owns the returned pointer.
  static CertificateEntry *X509ChainToEntry(const CertChain &chain);

 protected:
  bool ProcessX509Submission(const bstring &submission,
                             CertificateEntry *entry);


  bool ProcessPreCertSubmission(const bstring &submission,
                                CertificateEntry *entry);

 private:
  static bstring TbsCertificate(const CertChain &chain);
  static bstring TbsCertificate(const PreCertChain &chain);

  CertChecker *cert_checker_;
};
#endif
