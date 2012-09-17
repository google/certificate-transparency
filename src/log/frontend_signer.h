#ifndef FRONTEND_SIGNER_H
#define FRONTEND_SIGNER_H

#include <string>

#include "ct.pb.h"
#include "submission_handler.h"

class CertificateDB;
class LogSigner;
class SerialHasher;

class FrontendSigner {
 public:
  // Takes ownership of db and signer.
  FrontendSigner(CertificateDB *db, LogSigner *signer);

  // Takes ownership of db, signer and handler.
  FrontendSigner(CertificateDB *db, LogSigner *signer,
                 SubmissionHandler *handler);

  ~FrontendSigner();

  enum SubmitResult {
    LOGGED,
    PENDING,
    NEW,
    BAD_PEM_FORMAT,
    SUBMISSION_TOO_LONG,
    CERTIFICATE_VERIFY_ERROR,
    PRECERT_CHAIN_NOT_WELL_FORMED,
    UNKNOWN_ERROR,
  };

  SubmitResult QueueEntry(const bstring &data,
                          ct::SignedCertificateTimestamp *sct);

  SubmitResult QueueEntry(ct::CertificateEntry::Type type, const bstring data,
                          ct::SignedCertificateTimestamp *sct);

  static std::string SubmitResultString(SubmitResult result);

 private:
  CertificateDB *db_;
  SerialHasher *hasher_;
  LogSigner *signer_;
  SubmissionHandler *handler_;
  bstring ComputePrimaryKey(const ct::CertificateEntry &entry) const;

  void TimestampAndSign(ct::SignedCertificateTimestamp *sct) const;

  static SubmitResult GetSubmitError(SubmissionHandler::SubmitResult result);
};
#endif
