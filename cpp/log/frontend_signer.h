#ifndef CERT_TRANS_LOG_FRONTEND_SIGNER_H_
#define CERT_TRANS_LOG_FRONTEND_SIGNER_H_

#include <stdint.h>
#include <string>

#include "base/macros.h"
#include "log/consistent_store.h"
#include "log/logged_entry.h"

class LogSigner;

namespace util {
class Status;
}  // namespace util

namespace cert_trans {
class Database;
}  // namespace cert_trans


class FrontendSigner {
 public:
  // Does not take ownership of |db|, |store| or |signer|.
  FrontendSigner(cert_trans::Database* db, cert_trans::ConsistentStore* store,
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

  cert_trans::Database* const db_;
  cert_trans::ConsistentStore* const store_;
  LogSigner* const signer_;

  DISALLOW_COPY_AND_ASSIGN(FrontendSigner);
};

#endif  // CERT_TRANS_LOG_FRONTEND_SIGNER_H_
