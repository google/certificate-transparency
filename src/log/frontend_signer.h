#ifndef FRONTEND_SIGNER_H
#define FRONTEND_SIGNER_H

#include <stdint.h>
#include <string>

#include "ct.pb.h"
#include "submission_handler.h"

class Database;
class LogSigner;
class SerialHasher;

class FrontendSigner {
 public:
  // Takes ownership of |signer|.
  FrontendSigner(Database *db, LogSigner *signer);

  // Takes ownership of |signer| and |handler|.
  FrontendSigner(Database *db, LogSigner *signer, SubmissionHandler *handler);

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

  SubmitResult QueueEntry(const std::string &data,
                          ct::SignedCertificateTimestamp *sct);

  SubmitResult QueueEntry(ct::CertificateEntry::Type type,
                          const std::string data,
                          ct::SignedCertificateTimestamp *sct);

  static std::string SubmitResultString(SubmitResult result);

 private:
  Database *db_;
  SerialHasher *hasher_;
  LogSigner *signer_;
  SubmissionHandler *handler_;

  std::string ComputeCertificateHash(const ct::CertificateEntry &entry) const;

  void TimestampAndSign(ct::SignedCertificateTimestamp *sct) const;

  static SubmitResult GetSubmitError(SubmissionHandler::SubmitResult result);
};
#endif
