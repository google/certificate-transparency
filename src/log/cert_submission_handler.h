#ifndef CERT_SUBMISSION_HANDLER_H
#define CERT_SUBMISSION_HANDLER_H

#include <string>

#include "log/cert_checker.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"

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
    INVALID_PEM_ENCODED_CHAIN,
    INVALID_CERTIFICATE_CHAIN,
    PRECERT_CHAIN_NOT_WELL_FORMED,
    UNKNOWN_ROOT,
  };

  // entry should have the expected type set.
  SubmitResult ProcessSubmission(const std::string &submission,
                                 ct::LogEntry *entry);

  // For clients, to reconstruct the bytestring under the signature
  // from the observed chain. Does not check whether the entry
  // has valid format (i.e., does not check length limits).
  static void X509CertToEntry(const Cert &cert, ct::LogEntry *entry);

 private:
  SubmitResult ProcessX509Submission(const std::string &submission,
                                     ct::X509ChainEntry *entry);


  SubmitResult ProcessPreCertSubmission(const std::string &submission,
                                        ct::PrecertChainEntry *entry);

  static std::string TbsCertificate(const Cert &cert);
  static std::string TbsCertificate(const PreCertChain &chain);

  CertChecker *cert_checker_;

  static SubmitResult GetFormatError(Serializer::SerializeResult result);

  static SubmitResult GetVerifyError(CertChecker::CertVerifyResult result);
};
#endif
