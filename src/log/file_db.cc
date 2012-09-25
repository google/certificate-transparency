/* -*- indent-tabs-mode: nil -*- */

#include <map>
#include <set>
#include <stdint.h>
#include <utility> // for std::pair
#include <vector>

#include "ct.pb.h"
#include "file_db.h"
#include "file_storage.h"
#include "serializer.h"
#include "types.h"

using ct::SignedCertificateTimestamp;
using ct::LoggedCertificate;
using ct::SignedTreeHead;

const size_t FileDB::kTimestampBytesIndexed = 6;

FileDB::FileDB(FileStorage *cert_storage, FileStorage *tree_storage)
    : cert_storage_(cert_storage),
      tree_storage_(tree_storage),
      latest_tree_timestamp_(0) {
  BuildIndex();
}

FileDB::~FileDB() {
  delete cert_storage_;
  delete tree_storage_;
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
  FileStorage::FileStorageResult result =
      cert_storage_->CreateEntry(pending_key, data);
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
    if (cert_storage_->LookupEntry(pending_key, NULL) == FileStorage::OK)
      return ENTRY_ALREADY_LOGGED;
    return ENTRY_NOT_FOUND;
  }

  if (sequence_map_.find(sequence_number) != sequence_map_.end())
    return SEQUENCE_NUMBER_ALREADY_IN_USE;

  bstring cert_data;
  FileStorage::FileStorageResult result =
      cert_storage_->LookupEntry(pending_key, &cert_data);
  assert(result == FileStorage::OK);

  LoggedCertificate logged_cert;
  bool ret = logged_cert.ParseFromString(cert_data);
  assert(ret);
  assert(!logged_cert.has_sequence_number());
  logged_cert.set_sequence_number(sequence_number);
  logged_cert.SerializeToString(&cert_data);
  result = cert_storage_->UpdateEntry(pending_key, cert_data);
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
      cert_storage_->LookupEntry(certificate_key, &cert_data);
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
        cert_storage_->LookupEntry(it->second, &cert_data);
    assert(db_result == FileStorage::OK);

    LoggedCertificate logged_cert;
    bool ret = logged_cert.ParseFromString(cert_data);
    assert(ret);
    assert(logged_cert.sequence_number() == sequence_number);

    result->CopyFrom(logged_cert.sct());
  }

  return LOGGED;
}

Database::WriteResult
FileDB::WriteTreeHead(const SignedTreeHead &sth) {
  if (!sth.has_timestamp())
    return MISSING_TREE_HEAD_TIMESTAMP;
  // 6 bytes are good enough for some 9000 years.
  bstring timestamp_key =
      Serializer::SerializeUint(sth.timestamp(),
                                FileDB::kTimestampBytesIndexed);
  bstring data;
  bool ret = sth.SerializeToString(&data);
  assert(ret);

  FileStorage::FileStorageResult result =
      tree_storage_->CreateEntry(timestamp_key, data);
  if (result == FileStorage::ENTRY_ALREADY_EXISTS)
    return DUPLICATE_TREE_HEAD_TIMESTAMP;
  assert(result == FileStorage::OK);

  if (sth.timestamp() > latest_tree_timestamp_) {
    latest_tree_timestamp_ = sth.timestamp();
    latest_timestamp_key_ = timestamp_key;
  }

  return OK;
}

Database::LookupResult
FileDB::LatestTreeHead(SignedTreeHead *result) const {
  if (latest_tree_timestamp_ == 0)
    return NOT_FOUND;

  bstring tree_data;
  FileStorage::FileStorageResult db_result =
      tree_storage_->LookupEntry(latest_timestamp_key_, &tree_data);
  assert(db_result == FileStorage::OK);

  SignedTreeHead local_sth;

  bool ret = local_sth.ParseFromString(tree_data);
  assert(ret);
  assert(local_sth.timestamp() == latest_tree_timestamp_);

  result->CopyFrom(local_sth);
  return LOGGED;
}

void FileDB::BuildIndex() {
  pending_keys_ = cert_storage_->Scan();
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
    FileStorage::FileStorageResult result =
        cert_storage_->LookupEntry(*it2, &cert_data);
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

  // Now read the STH entries.
  std::set<bstring> sth_timestamps = tree_storage_->Scan();

  if (!sth_timestamps.empty())
    latest_timestamp_key_ = *sth_timestamps.rbegin();
  Deserializer::DeserializeResult result =
      Deserializer::DeserializeUint<uint64_t>(latest_timestamp_key_,
                                              FileDB::kTimestampBytesIndexed,
                                              &latest_tree_timestamp_);
  if (result != Deserializer::OK)
    abort();
}
