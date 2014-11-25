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
FileDB<Logged>::FileDB(cert_trans::FileStorage* cert_storage,
                       cert_trans::FileStorage* tree_storage)
    : cert_storage_(CHECK_NOTNULL(cert_storage)),
      tree_storage_(CHECK_NOTNULL(tree_storage)),
      latest_tree_timestamp_(0) {
  BuildIndex();
}


template <class Logged>
FileDB<Logged>::~FileDB() {
}


template <class Logged>
typename Database<Logged>::WriteResult FileDB<Logged>::CreateSequencedEntry_(
    const Logged& logged) {
  CHECK(logged.has_sequence_number());

  std::lock_guard<std::mutex> lock(lock_);

  // Check we don't already have something for this sequence number
  if (sequence_map_.find(logged.sequence_number()) != sequence_map_.end()) {
    LOG(WARNING) << "Attempting to re-use sequence number "
                 << logged.sequence_number() << " for entry:\n"
                 << logged.DebugString();
    return this->SEQUENCE_NUMBER_ALREADY_IN_USE;
  }

  const std::string hash(logged.Hash());

  std::string data;
  CHECK(logged.SerializeToString(&data));
  // Try to create.
  util::Status status(cert_storage_->CreateEntry(hash, data));
  if (status.CanonicalCode() == util::error::ALREADY_EXISTS) {
    return this->ENTRY_ALREADY_LOGGED;
  }
  assert(status.ok());
  CHECK(
      sequence_map_.insert(make_pair(logged.sequence_number(), hash)).second);
  return this->OK;
}


template <class Logged>
typename Database<Logged>::LookupResult FileDB<Logged>::LookupByHash(
    const std::string& hash, Logged* result) const {
  std::string cert_data;
  util::Status status(cert_storage_->LookupEntry(hash, &cert_data));
  if (status.CanonicalCode() == util::error::NOT_FOUND) {
    return this->NOT_FOUND;
  }
  assert(status.ok());

  Logged logged;
  bool ret = logged.ParseFromString(cert_data);
  assert(ret);

  if (result != nullptr) {
    result->CopyFrom(logged);
  }

  return this->LOOKUP_OK;
}


template <class Logged>
typename Database<Logged>::LookupResult FileDB<Logged>::LookupByIndex(
    uint64_t sequence_number, Logged* result) const {
  std::unique_lock<std::mutex> lock(lock_);

  std::map<uint64_t, std::string>::const_iterator it =
      sequence_map_.find(sequence_number);
  if (it == sequence_map_.end()) {
    return this->NOT_FOUND;
  }

  const std::string hash(it->second);
  // Now that we know which hash to load (which can never change for a
  // given sequence number), we can release the lock.
  lock.unlock();

  if (result != nullptr) {
    std::string cert_data;
    util::Status status(cert_storage_->LookupEntry(hash, &cert_data));
    assert(status.ok());

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

  std::unique_lock<std::mutex> lock(lock_);
  util::Status status(tree_storage_->CreateEntry(timestamp_key, data));
  if (status.CanonicalCode() == util::error::ALREADY_EXISTS) {
    return this->DUPLICATE_TREE_HEAD_TIMESTAMP;
  }
  assert(status.ok());

  if (sth.timestamp() > latest_tree_timestamp_) {
    latest_tree_timestamp_ = sth.timestamp();
    latest_timestamp_key_ = timestamp_key;
  }

  lock.unlock();
  callbacks_.Call(sth);

  return this->OK;
}


template <class Logged>
typename Database<Logged>::LookupResult FileDB<Logged>::LatestTreeHead(
    ct::SignedTreeHead* result) const {
  std::lock_guard<std::mutex> lock(lock_);

  return LatestTreeHeadNoLock(result);
}


template <class Logged>
int FileDB<Logged>::TreeSize() const {
  std::lock_guard<std::mutex> lock(lock_);

  CHECK_EQ(sequence_map_.size(), sequence_map_.rbegin()->first + 1);
  return sequence_map_.size();
}


template <class Logged>
void FileDB<Logged>::AddNotifySTHCallback(
    const typename Database<Logged>::NotifySTHCallback* callback) {
  std::unique_lock<std::mutex> lock(lock_);

  callbacks_.Add(callback);

  ct::SignedTreeHead sth;
  if (LatestTreeHeadNoLock(&sth) == this->LOOKUP_OK) {
    lock.unlock();
    (*callback)(sth);
  }
}


template <class Logged>
void FileDB<Logged>::RemoveNotifySTHCallback(
    const typename Database<Logged>::NotifySTHCallback* callback) {
  std::lock_guard<std::mutex> lock(lock_);

  callbacks_.Remove(callback);
}


template <class Logged>
void FileDB<Logged>::BuildIndex() {
  // Technically, this should only be called from the constructor, so
  // this should not be necessarily, but just to be sure...
  std::lock_guard<std::mutex> lock(lock_);

  const std::set<std::string> hashes(cert_storage_->Scan());
  for (const auto& hash : hashes) {
    std::string cert_data;
    // Read the data; tolerate no errors.
    util::Status status(cert_storage_->LookupEntry(hash, &cert_data));
    CHECK_EQ(status, util::Status::OK) << "Failed to read entry with hash "
                                       << hash;
    Logged logged;
    CHECK(logged.ParseFromString(cert_data)) << "Failed to parse entry with "
                                             << "hash " << hash;
    CHECK(logged.has_sequence_number()) << "No sequence number for entry with "
                                        << "hash " << hash;
    CHECK(sequence_map_.insert(std::pair<uint64_t, std::string>(
                                   logged.sequence_number(), hash)).second)
        << "Sequence number " << logged.sequence_number() << " already "
        << "assigned when inserting hash " << hash;
  }

  // Now read the STH entries.
  std::set<std::string> sth_timestamps = tree_storage_->Scan();
  if (!sth_timestamps.empty()) {
    latest_timestamp_key_ = *sth_timestamps.rbegin();
    CHECK_EQ(Deserializer::OK,
             Deserializer::DeserializeUint<uint64_t>(
                 latest_timestamp_key_, FileDB::kTimestampBytesIndexed,
                 &latest_tree_timestamp_));
  }
}


template <class Logged>
typename Database<Logged>::LookupResult FileDB<Logged>::LatestTreeHeadNoLock(
    ct::SignedTreeHead* result) const {
  if (latest_tree_timestamp_ == 0) {
    return this->NOT_FOUND;
  }

  std::string tree_data;
  CHECK_EQ(tree_storage_->LookupEntry(latest_timestamp_key_, &tree_data),
           util::Status::OK);

  CHECK(result->ParseFromString(tree_data));
  CHECK_EQ(result->timestamp(), latest_tree_timestamp_);

  return this->LOOKUP_OK;
}


#endif  // CERT_TRANS_LOG_FILE_DB_INL_H_
