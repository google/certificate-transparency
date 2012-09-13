#ifndef SUBMISSION_HANDLER_H
#define SUBMISSION_HANDLER_H

#include "cert_checker.h"
#include "ct.pb.h"
#include "serializer.h"
#include "types.h"

// The submission handler is responsible for parsing submissions and
// deciding whether they are accepted for logging.
class SubmissionHandler {
 public:
  SubmissionHandler() {}
  virtual ~SubmissionHandler() {}

  enum SubmitResult {
    OK,
    INVALID_TYPE,
    UNKNOWN_ERROR,
    EMPTY_SUBMISSION,
    SUBMISSION_TOO_LONG,
    CHAIN_NOT_LOADED,
    INVALID_PEM_ENCODED_CHAIN,
    INVALID_CERTIFICATE_CHAIN,
    PRECERT_CHAIN_NOT_WELL_FORMED,
    UNKNOWN_ROOT,
  };

  // entry should have the expected type set.
  SubmitResult ProcessSubmission(const bstring &submission,
                                 ct::CertificateEntry *entry);

 protected:
  virtual SubmitResult ProcessX509Submission(const bstring &submission,
                                             ct::CertificateEntry *entry);
  virtual SubmitResult ProcessPreCertSubmission(const bstring &submission,
                                                ct::CertificateEntry *entry);

  static SubmitResult GetFormatError(Serializer::SerializeResult result);

  static SubmitResult GetVerifyError(CertChecker::CertVerifyResult result);
};
#endif
