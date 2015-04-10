#ifndef FRONTEND_SIGNER_H
#define FRONTEND_SIGNER_H

#include <stdint.h>
#include <string>

#include "base/macros.h"
#include "log/consistent_store.h"
#include "log/logged_certificate.h"

template <class Logged>
class Database;
class LogSigner;

namespace util {
class Status;
}  // namespace util


class FrontendSigner {
 public:
  // Does not take ownership of |db|, |store| or |signer|.
  FrontendSigner(
      Database<cert_trans::LoggedCertificate>* db,
      cert_trans::ConsistentStore<cert_trans::LoggedCertificate>* store,
      LogSigner* signer);

  // Log the entry if it's not already in the database,
  // and return either a new timestamp-signature pair,
  // or a previously existing one. (Currently also copies the
  // entry to the sct but you shouldn't rely on this.)
  util::Status QueueEntry(const ct::LogEntry& entry,
                          ct::SignedCertificateTimestamp* sct);

 private:
  void TimestampAndSign(const ct::LogEntry& entry,
                        ct::SignedCertificateTimestamp* sct) const;

  Database<cert_trans::LoggedCertificate>* const db_;
  cert_trans::ConsistentStore<cert_trans::LoggedCertificate>* const store_;
  LogSigner* const signer_;

  DISALLOW_COPY_AND_ASSIGN(FrontendSigner);
};
#endif
