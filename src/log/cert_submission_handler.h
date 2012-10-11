#ifndef CERT_SUBMISSION_HANDLER_H
#define CERT_SUBMISSION_HANDLER_H

#include <string>

#include "cert_checker.h"
#include "ct.pb.h"
#include "serializer.h"

// Parse incoming submissions, do preliminary sanity checks and pass them
// through cert checker.
// Prepare for signing by parsing the input into an appropriate
// log entry structure.
class CertSubmissionHandler {
 public:
  // Does not take ownership of the cert_checker.
  explicit CertSubmissionHandler(CertChecker *cert_checker);
  ~CertSubmissionHandler() {}

  enum SubmitResult {
    OK,
    INVALID_TYPE,
    EMPTY_SUBMISSION,
    SUBMISSION_TOO_LONG,
    CHAIN_NOT_LOADED,
    INVALID_PEM_ENCODED_CHAIN,
    INVALID_CERTIFICATE_CHAIN,
    PRECERT_CHAIN_NOT_WELL_FORMED,
    UNKNOWN_ROOT,
  };

  // entry should have the expected type set.
  SubmitResult ProcessSubmission(const std::string &submission,
                                 ct::CertificateEntry *entry);

  // For clients, to reconstruct the bytestring under the signature
  // from the observed chain.
  static SubmitResult X509ChainToEntry(const CertChain &chain,
                                       ct::CertificateEntry *entry);

 private:
  SubmitResult ProcessX509Submission(const std::string &submission,
                                     ct::CertificateEntry *entry);


  SubmitResult ProcessPreCertSubmission(const std::string &submission,
                                        ct::CertificateEntry *entry);

  static std::string TbsCertificate(const CertChain &chain);
  static std::string TbsCertificate(const PreCertChain &chain);

  CertChecker *cert_checker_;

  static SubmitResult GetFormatError(Serializer::SerializeResult result);

  static SubmitResult GetVerifyError(CertChecker::CertVerifyResult result);
};
#endif
