/* -*- indent-tabs-mode: nil -*- */

#include <map>
#include <set>
#include <stdint.h>
#include <utility>  // for std::pair
#include <vector>

#include "ct.pb.h"
#include "file_db.h"
#include "file_storage.h"
#include "serializer.h"

using ct::SignedCertificateTimestamp;
using ct::LoggedCertificate;
using ct::SignedTreeHead;
using std::string;

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

Database::WriteResult FileDB::CreatePendingCertificateEntry_(
    const LoggedCertificate &logged_cert) {
  if (pending_hashes_.find(logged_cert.certificate_sha256_hash()) !=
      pending_hashes_.end())
    return DUPLICATE_CERTIFICATE_HASH;

  // ??? We've already asserted that there is no sequence number!
  LoggedCertificate local;
  local.CopyFrom(logged_cert);
  local.clear_sequence_number();

  string data;
  bool ret = local.SerializeToString(&data);
  assert(ret);
  // Try to create.
  FileStorage::FileStorageResult result =
      cert_storage_->CreateEntry(logged_cert.certificate_sha256_hash(), data);
  if (result == FileStorage::ENTRY_ALREADY_EXISTS)
    return DUPLICATE_CERTIFICATE_HASH;
  assert(result == FileStorage::OK);
  pending_hashes_.insert(logged_cert.certificate_sha256_hash());
  return OK;
}

std::set<string> FileDB::PendingHashes() const {
  return pending_hashes_;
}

Database::WriteResult FileDB::AssignCertificateSequenceNumber(
    const string &certificate_sha256_hash, uint64_t sequence_number) {
  std::set<string>::iterator pending_it =
      pending_hashes_.find(certificate_sha256_hash);
  if (pending_it == pending_hashes_.end()) {
    // Caller should have ensured we don't get here...
    if (cert_storage_->LookupEntry(certificate_sha256_hash, NULL) ==
        FileStorage::OK)
      return ENTRY_ALREADY_LOGGED;
    return ENTRY_NOT_FOUND;
  }

  if (sequence_map_.find(sequence_number) != sequence_map_.end())
    return SEQUENCE_NUMBER_ALREADY_IN_USE;

  string cert_data;
  FileStorage::FileStorageResult result =
      cert_storage_->LookupEntry(certificate_sha256_hash, &cert_data);
  assert(result == FileStorage::OK);

  LoggedCertificate logged_cert;
  bool ret = logged_cert.ParseFromString(cert_data);
  assert(ret);
  assert(!logged_cert.has_sequence_number());
  logged_cert.set_sequence_number(sequence_number);
  logged_cert.SerializeToString(&cert_data);
  result = cert_storage_->UpdateEntry(certificate_sha256_hash, cert_data);
  assert(result == FileStorage::OK);

  pending_hashes_.erase(pending_it);
  sequence_map_.insert(std::pair<uint64_t, string>(sequence_number,
                                                    certificate_sha256_hash));
  return OK;
}

Database::LookupResult FileDB::LookupCertificateByHash(
    const string &certificate_sha256_hash,
    LoggedCertificate *result) const {
  string cert_data;
  FileStorage::FileStorageResult db_result =
      cert_storage_->LookupEntry(certificate_sha256_hash, &cert_data);
  if (db_result == FileStorage::NOT_FOUND)
    return NOT_FOUND;
  assert(db_result == FileStorage::OK);

  LoggedCertificate logged_cert;
  bool ret = logged_cert.ParseFromString(cert_data);
  assert(ret);

  if (result != NULL)
    result->CopyFrom(logged_cert);

  return LOOKUP_OK;
}

Database::LookupResult FileDB::LookupCertificateByIndex(
    uint64_t sequence_number, LoggedCertificate *result) const {
  std::map<uint64_t, string>::const_iterator it =
      sequence_map_.find(sequence_number);
  if (it == sequence_map_.end())
    return NOT_FOUND;

  if (result != NULL) {
    string cert_data;
    FileStorage::FileStorageResult db_result =
        cert_storage_->LookupEntry(it->second, &cert_data);
    assert(db_result == FileStorage::OK);

    LoggedCertificate logged_cert;
    bool ret = logged_cert.ParseFromString(cert_data);
    assert(ret);
    assert(logged_cert.sequence_number() == sequence_number);

    result->CopyFrom(logged_cert);
  }

  return LOOKUP_OK;
}

Database::WriteResult FileDB::WriteTreeHead_(const SignedTreeHead &sth) {
  // 6 bytes are good enough for some 9000 years.
  string timestamp_key =
      Serializer::SerializeUint(sth.timestamp(),
                                FileDB::kTimestampBytesIndexed);
  string data;
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

  string tree_data;
  FileStorage::FileStorageResult db_result =
      tree_storage_->LookupEntry(latest_timestamp_key_, &tree_data);
  assert(db_result == FileStorage::OK);

  SignedTreeHead local_sth;

  bool ret = local_sth.ParseFromString(tree_data);
  assert(ret);
  assert(local_sth.timestamp() == latest_tree_timestamp_);

  result->CopyFrom(local_sth);
  return LOOKUP_OK;
}

void FileDB::BuildIndex() {
  pending_hashes_ = cert_storage_->Scan();
  if (pending_hashes_.empty())
    return;
  // Now read the entries: remove those that have a sequence number
  // from the set of pending entries and add them to the index.
  std::set<string>::iterator it = pending_hashes_.begin();
  do {
    // Increment before any erase operations.
    std::set<string>::iterator it2 = it++;
    string cert_data;
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
          std::pair<uint64_t, string>(logged_cert.sequence_number(), *it2));
      pending_hashes_.erase(it2);
    }
  } while (it != pending_hashes_.end());

  // Now read the STH entries.
  std::set<string> sth_timestamps = tree_storage_->Scan();

  if (!sth_timestamps.empty()) {
    latest_timestamp_key_ = *sth_timestamps.rbegin();
    Deserializer::DeserializeResult result =
        Deserializer::DeserializeUint<uint64_t>(latest_timestamp_key_,
                                                FileDB::kTimestampBytesIndexed,
                                                &latest_tree_timestamp_);
    if (result != Deserializer::OK)
      abort();
  }
}
