#include <glog/logging.h>

#include "ct.pb.h"
#include "database.h"
#include "frontend_signer.h"
#include "log_signer.h"
#include "serial_hasher.h"
#include "util.h"

using ct::CertificateEntry;
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
FrontendSigner::QueueEntry(const CertificateEntry &entry,
                           SignedCertificateTimestamp *sct) {
  // Check if the entry already exists.
  string sha256_hash = ComputeCertificateHash(entry);
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

  LoggedCertificate new_cert;
  new_cert.set_certificate_sha256_hash(sha256_hash);
  new_cert.mutable_sct()->mutable_entry()->CopyFrom(entry);

  TimestampAndSign(new_cert.mutable_sct());

  Database::WriteResult write_result =
      db_->CreatePendingCertificateEntry(new_cert);

  // Assume for now that nobody interfered while we were busy signing.
  CHECK_EQ(Database::OK, write_result);
  if (sct != NULL)
    sct->CopyFrom(new_cert.sct());
  return NEW;
}

string
FrontendSigner::ComputeCertificateHash(const CertificateEntry &entry) const {
  // Compute the SHA-256 hash of the leaf certificate.
  return Sha256Hasher::Sha256Digest(entry.leaf_certificate());
}

void FrontendSigner::TimestampAndSign(SignedCertificateTimestamp *sct) const {
  sct->set_timestamp(util::TimeInMilliseconds());
  // The submission handler has already verified the format of this entry,
  // so this should never fail.
  CHECK_EQ(LogSigner::OK, signer_->SignCertificateTimestamp(sct));
}
