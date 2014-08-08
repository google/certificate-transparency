#ifndef FRONTEND_SIGNER_H
#define FRONTEND_SIGNER_H

#include <stdint.h>
#include <string>

#include "base/macros.h"
#include "log/logged_certificate.h"

template <class Logged> class Database;
class LogSigner;

class FrontendSigner {
 public:
  enum SubmitResult {
    NEW,
    DUPLICATE,
  };

  // Does not take ownership of |signer|.
  FrontendSigner(Database<ct::LoggedCertificate> *db, LogSigner *signer);

  // Log the entry if it's not already in the database,
  // and return either a new timestamp-signature pair,
  // or a previously existing one. (Currently also copies the
  // entry to the sct but you shouldn't rely on this.)
  SubmitResult QueueEntry(const ct::LogEntry &entry,
                          ct::SignedCertificateTimestamp *sct);

 private:
  void TimestampAndSign(const ct::LogEntry &entry,
                        ct::SignedCertificateTimestamp *sct) const;

  Database<ct::LoggedCertificate>* const db_;
  LogSigner* const signer_;

  DISALLOW_COPY_AND_ASSIGN(FrontendSigner);
};
#endif
