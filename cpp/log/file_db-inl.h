/* -*- indent-tabs-mode: nil -*- */
#ifndef CERT_TRANS_LOG_FILE_DB_INL_H_
#define CERT_TRANS_LOG_FILE_DB_INL_H_

#include "log/file_db.h"

#include <glog/logging.h>
#include <map>
#include <set>
#include <stdint.h>
#include <utility>  // for std::pair
#include <vector>

#include "log/file_storage.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"


template <class Logged>
const size_t FileDB<Logged>::kTimestampBytesIndexed = 6;

template <class Logged>
FileDB<Logged>::FileDB(FileStorage* cert_storage, FileStorage* tree_storage)
    : cert_storage_(cert_storage),
      tree_storage_(tree_storage),
      latest_tree_timestamp_(0) {
  BuildIndex();
}

template <class Logged>
FileDB<Logged>::~FileDB() {
  delete cert_storage_;
  delete tree_storage_;
}

template <class Logged>
typename Database<Logged>::WriteResult FileDB<Logged>::CreatePendingEntry_(
    const Logged& logged) {
  const std::string hash = logged.Hash();
  if (pending_hashes_.find(hash) != pending_hashes_.end())
    return this->DUPLICATE_CERTIFICATE_HASH;

  // ??? We've already asserted that there is no sequence number!
  Logged local;
  local.CopyFrom(logged);
  local.clear_sequence_number();

  std::string data;
  CHECK(local.SerializeToString(&data));
  // Try to create.
  FileStorage::FileStorageResult result =
      cert_storage_->CreateEntry(hash, data);
  if (result == FileStorage::ENTRY_ALREADY_EXISTS)
    return this->DUPLICATE_CERTIFICATE_HASH;
  assert(result == FileStorage::OK);
  pending_hashes_.insert(hash);
  return this->OK;
}

template <class Logged>
std::set<std::string> FileDB<Logged>::PendingHashes() const {
  return pending_hashes_;
}

template <class Logged>
typename Database<Logged>::WriteResult FileDB<Logged>::AssignSequenceNumber(
    const std::string& hash, uint64_t sequence_number) {
  std::set<std::string>::iterator pending_it = pending_hashes_.find(hash);
  if (pending_it == pending_hashes_.end()) {
    // Caller should have ensured we don't get here...
    if (cert_storage_->LookupEntry(hash, NULL) == FileStorage::OK)
      return this->ENTRY_ALREADY_LOGGED;
    return this->ENTRY_NOT_FOUND;
  }

  if (sequence_map_.find(sequence_number) != sequence_map_.end())
    return this->SEQUENCE_NUMBER_ALREADY_IN_USE;

  std::string cert_data;
  FileStorage::FileStorageResult result =
      cert_storage_->LookupEntry(hash, &cert_data);
  assert(result == FileStorage::OK);

  Logged logged;
  bool ret = logged.ParseFromString(cert_data);
  assert(ret);
  assert(!logged.has_sequence_number());
  logged.set_sequence_number(sequence_number);
  logged.SerializeToString(&cert_data);
  result = cert_storage_->UpdateEntry(hash, cert_data);
  assert(result == FileStorage::OK);

  pending_hashes_.erase(pending_it);
  sequence_map_.insert(
      std::pair<uint64_t, std::string>(sequence_number, hash));
  return this->OK;
}

template <class Logged>
typename Database<Logged>::LookupResult FileDB<Logged>::LookupByHash(
    const std::string& hash) const {
  return LookupByHash(hash, NULL);
}

template <class Logged>
typename Database<Logged>::LookupResult FileDB<Logged>::LookupByHash(
    const std::string& hash, Logged* result) const {
  std::string cert_data;
  FileStorage::FileStorageResult db_result =
      cert_storage_->LookupEntry(hash, &cert_data);
  if (db_result == FileStorage::NOT_FOUND)
    return this->NOT_FOUND;
  assert(db_result == FileStorage::OK);

  Logged logged;
  bool ret = logged.ParseFromString(cert_data);
  assert(ret);

  if (result != NULL)
    result->CopyFrom(logged);

  return this->LOOKUP_OK;
}

template <class Logged>
typename Database<Logged>::LookupResult FileDB<Logged>::LookupByIndex(
    uint64_t sequence_number, Logged* result) const {
  std::map<uint64_t, std::string>::const_iterator it =
      sequence_map_.find(sequence_number);
  if (it == sequence_map_.end())
    return this->NOT_FOUND;

  if (result != NULL) {
    std::string cert_data;
    FileStorage::FileStorageResult db_result =
        cert_storage_->LookupEntry(it->second, &cert_data);
    assert(db_result == FileStorage::OK);

    Logged logged;
    bool ret = logged.ParseFromString(cert_data);
    assert(ret);
    assert(logged.sequence_number() == sequence_number);

    result->CopyFrom(logged);
  }

  return this->LOOKUP_OK;
}

template <class Logged>
typename Database<Logged>::WriteResult FileDB<Logged>::WriteTreeHead_(
    const ct::SignedTreeHead& sth) {
  // 6 bytes are good enough for some 9000 years.
  std::string timestamp_key =
      Serializer::SerializeUint(sth.timestamp(),
                                FileDB::kTimestampBytesIndexed);
  std::string data;
  bool ret = sth.SerializeToString(&data);
  assert(ret);

  FileStorage::FileStorageResult result =
      tree_storage_->CreateEntry(timestamp_key, data);
  if (result == FileStorage::ENTRY_ALREADY_EXISTS)
    return this->DUPLICATE_TREE_HEAD_TIMESTAMP;
  assert(result == FileStorage::OK);

  if (sth.timestamp() > latest_tree_timestamp_) {
    latest_tree_timestamp_ = sth.timestamp();
    latest_timestamp_key_ = timestamp_key;
  }

  return this->OK;
}

template <class Logged>
typename Database<Logged>::LookupResult FileDB<Logged>::LatestTreeHead(
    ct::SignedTreeHead* result) const {
  if (latest_tree_timestamp_ == 0)
    return this->NOT_FOUND;

  std::string tree_data;
  FileStorage::FileStorageResult db_result =
      tree_storage_->LookupEntry(latest_timestamp_key_, &tree_data);
  assert(db_result == FileStorage::OK);

  ct::SignedTreeHead local_sth;

  bool ret = local_sth.ParseFromString(tree_data);
  assert(ret);
  assert(local_sth.timestamp() == latest_tree_timestamp_);

  result->CopyFrom(local_sth);
  return this->LOOKUP_OK;
}

template <class Logged>
void FileDB<Logged>::BuildIndex() {
  pending_hashes_ = cert_storage_->Scan();
  if (pending_hashes_.empty())
    return;
  // Now read the entries: remove those that have a sequence number
  // from the set of pending entries and add them to the index.
  std::set<std::string>::iterator it = pending_hashes_.begin();
  do {
    // Increment before any erase operations.
    std::set<std::string>::iterator it2 = it++;
    std::string cert_data;
    // Read the data; tolerate no errors.
    FileStorage::FileStorageResult result =
        cert_storage_->LookupEntry(*it2, &cert_data);
    if (result != FileStorage::OK)
      abort();
    Logged logged;
    if (!logged.ParseFromString(cert_data))
      abort();
    if (logged.has_sequence_number()) {
      sequence_map_.insert(
          std::pair<uint64_t, std::string>(logged.sequence_number(), *it2));
      pending_hashes_.erase(it2);
    }
  } while (it != pending_hashes_.end());

  // Now read the STH entries.
  std::set<std::string> sth_timestamps = tree_storage_->Scan();

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

#endif  // CERT_TRANS_LOG_FILE_DB_INL_H_
