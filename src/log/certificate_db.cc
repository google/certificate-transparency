/* -*- indent-tabs-mode: nil -*- */

#include <map>
#include <set>
#include <stdint.h>
#include <utility> // for std::pair
#include <vector>

#include "certificate_db.h"
#include "ct.pb.h"
#include "file_storage.h"
#include "types.h"

using ct::SignedCertificateTimestamp;
using ct::LoggedCertificate;

FileDB::FileDB(FileStorage *storage)
    : storage_(storage) {
  BuildIndex();
}

FileDB::~FileDB() {
  delete storage_;
}

Database::WriteResult FileDB::CreatePendingCertificateEntry(
    const bstring &pending_key, const SignedCertificateTimestamp &sct) {
  if (pending_keys_.find(pending_key) != pending_keys_.end())
    return ENTRY_ALREADY_PENDING;

  bstring data;
  LoggedCertificate logged_cert;
  logged_cert.mutable_sct()->CopyFrom(sct);
  logged_cert.set_certificate_key(pending_key);

  bool ret = logged_cert.SerializeToString(&data);
  assert(ret);
  // Try to create.
  FileStorage::FileStorageResult result = storage_->CreateEntry(pending_key,
                                                                data);
  if (result == FileStorage::ENTRY_ALREADY_EXISTS)
    // It's not pending, so it must be logged.
    return ENTRY_ALREADY_LOGGED;
  assert(result == FileStorage::OK);
  pending_keys_.insert(pending_key);
  return OK;
}

std::set<bstring> FileDB::PendingKeys() const {
  return pending_keys_;
}

Database::WriteResult FileDB::AssignCertificateSequenceNumber(
    const bstring &pending_key, uint64_t sequence_number) {
  std::set<bstring>::iterator pending_it = pending_keys_.find(pending_key);
  if (pending_it == pending_keys_.end()) {
    // Caller should have ensured we don't get here...
    if (storage_->LookupEntry(pending_key, NULL) == FileStorage::OK)
      return ENTRY_ALREADY_LOGGED;
    return ENTRY_NOT_FOUND;
  }

  if (sequence_map_.find(sequence_number) != sequence_map_.end())
    return SEQUENCE_NUMBER_ALREADY_IN_USE;

  bstring cert_data;
  FileStorage::FileStorageResult result = storage_->LookupEntry(pending_key,
                                                                &cert_data);
  assert(result == FileStorage::OK);

  LoggedCertificate logged_cert;
  bool ret = logged_cert.ParseFromString(cert_data);
  assert(ret);
  assert(!logged_cert.has_sequence_number());
  logged_cert.set_sequence_number(sequence_number);
  logged_cert.SerializeToString(&cert_data);
  result = storage_->UpdateEntry(pending_key, cert_data);
  assert(result == FileStorage::OK);

  pending_keys_.erase(pending_it);
  sequence_map_.insert(std::pair<uint64_t, bstring>(sequence_number,
                                                    pending_key));
  return OK;
}

Database::LookupResult FileDB::LookupCertificateEntry(
    const bstring &certificate_key, uint64_t *sequence_number,
    SignedCertificateTimestamp *result) const {
  bstring cert_data;
  FileStorage::FileStorageResult db_result =
      storage_->LookupEntry(certificate_key, &cert_data);
  if (db_result == FileStorage::NOT_FOUND)
    return NOT_FOUND;
  assert (db_result == FileStorage::OK);

  LoggedCertificate logged_cert;
  bool ret = logged_cert.ParseFromString(cert_data);
  assert(ret);

  if (result != NULL)
    result->CopyFrom(logged_cert.sct());

  if (logged_cert.has_sequence_number()) {
    if (sequence_number != NULL)
      *sequence_number = logged_cert.sequence_number();
    return LOGGED;
  }

  return PENDING;
}

Database::LookupResult FileDB::LookupCertificateEntry(
    uint64_t sequence_number, SignedCertificateTimestamp *result) const {
  std::map<uint64_t, bstring>::const_iterator it =
      sequence_map_.find(sequence_number);
  if (it == sequence_map_.end())
    return NOT_FOUND;

  if (result != NULL) {
    bstring cert_data;
    FileStorage::FileStorageResult db_result =
        storage_->LookupEntry(it->second, &cert_data);
    assert(db_result == FileStorage::OK);

    LoggedCertificate logged_cert;
    bool ret = logged_cert.ParseFromString(cert_data);
    assert(ret);
    assert(logged_cert.sequence_number() == sequence_number);

    result->CopyFrom(logged_cert.sct());
  }

  return LOGGED;
}

void FileDB::BuildIndex() {
  pending_keys_ = storage_->Scan();
  if (pending_keys_.empty())
    return;
  // Now read the entries: remove those that have a sequence number
  // from the set of pending entries and add them to the index.
  std::set<bstring>::iterator it = pending_keys_.begin();
  do {
    // Increment before any erase operations.
    std::set<bstring>::iterator it2 = it++;
    bstring cert_data;
    // Read the data; tolerate no errors.
    FileStorage::FileStorageResult result = storage_->LookupEntry(*it2,
                                                                  &cert_data);
    if (result != FileStorage::OK)
      abort();
    LoggedCertificate logged_cert;
    if (!logged_cert.ParseFromString(cert_data))
      abort();
    if (logged_cert.has_sequence_number()) {
      sequence_map_.insert(
          std::pair<uint64_t, bstring>(logged_cert.sequence_number(), *it2));
      pending_keys_.erase(it2);
    }
  } while (it != pending_keys_.end());
}
