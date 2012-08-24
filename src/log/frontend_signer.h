#ifndef FRONTEND_SIGNER_H
#define FRONTEND_SIGNER_H

#include "ct.pb.h"
#include "frontend_signer.h"
#include "log_db.h"
#include "log_signer.h"
#include "submission_handler.h"

class SerialHasher;

class FrontendSigner {
 public:
  // Takes ownership of db and signer.
  FrontendSigner(LogDB *db, LogSigner *signer);

  // Takes ownership of db, signer and handler.
  FrontendSigner(LogDB *db, LogSigner *signer, SubmissionHandler *handler);

  ~FrontendSigner();

  LogDB::Status QueueEntry(const bstring &data, SignedCertificateHash *sch);

  LogDB::Status QueueEntry(CertificateEntry::Type type, const bstring data,
                           SignedCertificateHash *sch);

 private:
  LogDB *db_;
  SerialHasher *hasher_;
  LogSigner *signer_;
  SubmissionHandler *handler_;
  bstring ComputePrimaryKey(const CertificateEntry &entry) const;

  void TimestampAndSign(SignedCertificateHash *sch) const;
};
#endif
