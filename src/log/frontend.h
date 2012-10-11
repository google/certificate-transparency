#ifndef FRONTEND_H
#define FRONTEND_H

#include "ct.pb.h"
#include "cert_submission_handler.h"

class FrontendSigner;

// Frontend for accepting new submissions.
class Frontend {
 public:
  // Takes ownership of the handler and signer.
  Frontend(CertSubmissionHandler *handler, FrontendSigner *signer);
  ~Frontend();

  enum SubmitResult {
    NEW,
    DUPLICATE,
    BAD_PEM_FORMAT,
    SUBMISSION_TOO_LONG,
    CERTIFICATE_VERIFY_ERROR,
    PRECERT_CHAIN_NOT_WELL_FORMED,
  };

  SubmitResult QueueEntry(ct::CertificateEntry::Type type,
                          const std::string &data,
                          ct::SignedCertificateTimestamp *sct);

  static std::string SubmitResultString(SubmitResult result);

 private:
  CertSubmissionHandler *handler_;
  FrontendSigner *signer_;

  static SubmitResult
  GetSubmitError(CertSubmissionHandler::SubmitResult result);
};
#endif
