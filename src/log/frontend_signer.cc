#include <assert.h>
#include <stdint.h>

#include "ct.pb.h"
#include "frontend_signer.h"
#include "log_db.h"
#include "log_signer.h"
#include "serial_hasher.h"
#include "submission_handler.h"
#include "util.h"

FrontendSigner::FrontendSigner(LogDB *db, LogSigner *signer)
    : db_(db),
      hasher_(new Sha256Hasher),
      signer_(signer),
      // Default handler.
      handler_(new SubmissionHandler()) {
  assert(signer_ != NULL);
  assert(db_ != NULL);
}

FrontendSigner::FrontendSigner(LogDB *db, LogSigner *signer,
                               SubmissionHandler *handler)
    : db_(db),
      hasher_(new Sha256Hasher),
      signer_(signer),
      handler_(handler) {
  assert(signer_ != NULL);
  assert(db_ != NULL);
  assert(handler_ != NULL);
}

FrontendSigner::~FrontendSigner() {
  delete db_;
  delete hasher_;
  delete signer_;
  delete handler_;
}

LogDB::Status FrontendSigner::QueueEntry(const bstring &data,
                                         SignedCertificateHash *sch) {
  return QueueEntry(CertificateEntry::X509_ENTRY, data, sch);
}

LogDB::Status FrontendSigner::QueueEntry(CertificateEntry::Type type,
                                         const bstring data,
                                         SignedCertificateHash *sch) {
  // Verify the submission and compute signed and unsigned parts.
  CertificateEntry *entry = handler_->ProcessSubmission(type, data);
  if (entry == NULL)
    return LogDB::REJECTED;

  // Check if the entry already exists.
  bstring primary_key = ComputePrimaryKey(*entry);
  assert(!primary_key.empty());

  bstring record;
  LogDB::Status status = db_->LookupEntry(primary_key, LogDB::ANY, &record);
  if (status == LogDB::LOGGED || status == LogDB::PENDING) {
    if (sch != NULL)
      sch->ParseFromString(record);
    delete entry;
    return status;
  }

  assert(status == LogDB::NOT_FOUND);

  SignedCertificateHash local_sch;
  local_sch.mutable_entry()->CopyFrom(*entry);
  // TODO(ekasper): switch to (Boost?) smart pointers.
  delete entry;

  TimestampAndSign(&local_sch);

  local_sch.SerializeToString(&record);
  status = db_->WriteEntry(primary_key, record);

  // Assume for now that nobody interfered while we were busy signing.
  assert(status == LogDB::NEW);
  if (sch != NULL)
    sch->CopyFrom(local_sch);
  return status;
}

bstring FrontendSigner::ComputePrimaryKey(const CertificateEntry &entry) const {
  // Compute the SHA-256 hash of the leaf certificate.
  hasher_->Reset();
  hasher_->Update(entry.leaf_certificate());
  return hasher_->Final();
}

void FrontendSigner::TimestampAndSign(SignedCertificateHash *sch) const {
  sch->set_timestamp(util::TimeInMilliseconds());
  signer_->SignCertificateHash(sch);
}
