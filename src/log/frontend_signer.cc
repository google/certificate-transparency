#include <glog/logging.h>

#include "ct.pb.h"
#include "database.h"
#include "frontend_signer.h"
#include "log_signer.h"
#include "serializer.h"
#include "util.h"

using ct::LogEntry;
using ct::LoggedCertificate;
using ct::SignedCertificateTimestamp;
using std::string;

FrontendSigner::FrontendSigner(Database *db, LogSigner *signer)
    : db_(db),
      signer_(signer) {}

FrontendSigner::~FrontendSigner() {
  delete signer_;
}

FrontendSigner::SubmitResult
FrontendSigner::QueueEntry(const LogEntry &entry,
                           SignedCertificateTimestamp *sct) {
  // Check if the entry already exists.
  string sha256_hash = Serializer::CertificateSha256Hash(entry);
  assert(!sha256_hash.empty());

  LoggedCertificate logged_cert;
  Database::LookupResult db_result =
      db_->LookupCertificateByHash(sha256_hash, &logged_cert);

  if (db_result == Database::LOOKUP_OK) {
    if (sct != NULL)
      sct->CopyFrom(logged_cert.sct());

    return DUPLICATE;
  }

  CHECK_EQ(Database::NOT_FOUND, db_result);

  SignedCertificateTimestamp local_sct;
  TimestampAndSign(entry, &local_sct);

  LoggedCertificate new_cert;
  new_cert.set_certificate_sha256_hash(sha256_hash);
  new_cert.mutable_sct()->CopyFrom(local_sct);
  new_cert.mutable_entry()->CopyFrom(entry);

  Database::WriteResult write_result =
      db_->CreatePendingCertificateEntry(new_cert);

  // Assume for now that nobody interfered while we were busy signing.
  CHECK_EQ(Database::OK, write_result);
  if (sct != NULL)
    sct->CopyFrom(new_cert.sct());
  return NEW;
}

void FrontendSigner::TimestampAndSign(const LogEntry &entry,
                                      SignedCertificateTimestamp *sct) const {
  sct->set_version(ct::V1);
  sct->set_timestamp(util::TimeInMilliseconds());
  sct->clear_extension();
  // The submission handler has already verified the format of this entry,
  // so this should never fail.
  CHECK_EQ(LogSigner::OK, signer_->SignCertificateTimestamp(entry, sct));
}
