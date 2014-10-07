/* -*- indent-tabs-mode: nil -*- */
#include "log/frontend_signer.h"

#include <glog/logging.h>

#include "log/database.h"
#include "log/log_signer.h"
#include "merkletree/serial_hasher.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"
#include "util/util.h"

using ct::LogEntry;
using ct::SignedCertificateTimestamp;
using std::string;

FrontendSigner::FrontendSigner(Database<cert_trans::LoggedCertificate> *db,
                               LogSigner *signer)
    : db_(db),
      signer_(signer) {}

FrontendSigner::SubmitResult
FrontendSigner::QueueEntry(const LogEntry &entry,
                           SignedCertificateTimestamp *sct) {
  // Check if the entry already exists.
  // TODO(ekasper): switch to using SignedEntryWithType as the DB key.
  string sha256_hash =
      Sha256Hasher::Sha256Digest(Serializer::LeafCertificate(entry));
  assert(!sha256_hash.empty());

  cert_trans::LoggedCertificate logged;
  Database<cert_trans::LoggedCertificate>::LookupResult db_result =
      db_->LookupByHash(sha256_hash, &logged);

  if (db_result == Database<cert_trans::LoggedCertificate>::LOOKUP_OK) {
    if (sct != NULL)
      sct->CopyFrom(logged.sct());

    return DUPLICATE;
  }

  CHECK_EQ(Database<cert_trans::LoggedCertificate>::NOT_FOUND, db_result);

  SignedCertificateTimestamp local_sct;
  TimestampAndSign(entry, &local_sct);

  cert_trans::LoggedCertificate new_logged;
  new_logged.mutable_sct()->CopyFrom(local_sct);
  new_logged.mutable_entry()->CopyFrom(entry);
  CHECK_EQ(new_logged.Hash(), sha256_hash);

  Database<cert_trans::LoggedCertificate>::WriteResult write_result =
      db_->CreatePendingEntry(new_logged);

  // Assume for now that nobody interfered while we were busy signing.
  CHECK_EQ(Database<cert_trans::LoggedCertificate>::OK, write_result);
  if (sct != NULL)
    sct->CopyFrom(new_logged.sct());
  return NEW;
}

void FrontendSigner::TimestampAndSign(const LogEntry &entry,
                                      SignedCertificateTimestamp *sct) const {
  sct->set_version(ct::V1);
  sct->set_timestamp(util::TimeInMilliseconds());
  sct->clear_extensions();
  // The submission handler has already verified the format of this entry,
  // so this should never fail.
  CHECK_EQ(LogSigner::OK, signer_->SignCertificateTimestamp(entry, sct));
}
