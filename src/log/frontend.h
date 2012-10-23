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

  struct FrontendStats {
    FrontendStats()
  : x509_accepted(0),
    x509_duplicates(0),
    x509_bad_pem_certs(0),
    x509_too_long_certs(0),
    x509_verify_errors(0),
    precert_accepted(0),
    precert_duplicates(0),
    precert_bad_pem_certs(0),
    precert_too_long_certs(0),
    precert_verify_errors(0),
    precert_format_errors(0) {}

    FrontendStats(int x509_accepted_,
                  int x509_duplicates_,
                  int x509_bad_pem_certs_,
                  int x509_too_long_certs_,
                  int x509_verify_errors_,
                  int precert_accepted_,
                  int precert_duplicates_,
                  int precert_bad_pem_certs_,
                  int precert_too_long_certs_,
                  int precert_verify_errors_,
                  int precert_format_errors_)
        : x509_accepted(x509_accepted_),
          x509_duplicates(x509_duplicates_),
          x509_bad_pem_certs(x509_bad_pem_certs_),
          x509_too_long_certs(x509_too_long_certs_),
          x509_verify_errors(x509_verify_errors_),
          precert_accepted(precert_accepted_),
          precert_duplicates(precert_duplicates_),
          precert_bad_pem_certs(precert_bad_pem_certs_),
          precert_too_long_certs(precert_too_long_certs_),
          precert_verify_errors(precert_verify_errors_),
          precert_format_errors(precert_format_errors_) {}

    int x509_accepted;
    int x509_duplicates;
    int x509_bad_pem_certs;
    int x509_too_long_certs;
    int x509_verify_errors;
    int precert_accepted;
    int precert_duplicates;
    int precert_bad_pem_certs;
    int precert_too_long_certs;
    int precert_verify_errors;
    int precert_format_errors;
  };

  void GetStats(FrontendStats *stats) const;

  SubmitResult QueueEntry(ct::LogEntryType type,
                          const std::string &data,
                          ct::SignedCertificateTimestamp *sct);

  static std::string SubmitResultString(SubmitResult result);

 private:
  CertSubmissionHandler *handler_;
  FrontendSigner *signer_;
  FrontendStats stats_;

  static SubmitResult
  GetSubmitError(CertSubmissionHandler::SubmitResult result);
  void UpdateStats(ct::LogEntryType type, SubmitResult result);
  void UpdateX509Stats(SubmitResult result);
  void UpdatePrecertStats(SubmitResult result);
};
#endif
