/* -*- indent-tabs-mode: nil -*- */
#ifndef CERT_TRANS_LOG_FILE_DB_INL_H_
#define CERT_TRANS_LOG_FILE_DB_INL_H_

#include "log/file_db.h"

#include <glog/logging.h>
#include <map>
#include <set>
#include <stdint.h>
#include <string>
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
  CHECK_GE(logged.sequence_number(), 0);

  std::lock_guard<std::mutex> lock(lock_);

  if (logged.sequence_number() < dense_entries_.size() ||
      sparse_entries_.find(logged.sequence_number()) !=
          sparse_entries_.end()) {
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
  CHECK_EQ(status, util::Status::OK);

  InsertEntryMapping(logged.sequence_number(), hash);

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
  CHECK_EQ(status, util::Status::OK);

  Logged logged;
  CHECK(logged.ParseFromString(cert_data));
  CHECK_EQ(logged.Hash(), hash);

  if (result) {
    logged.Swap(result);
  }

  return this->LOOKUP_OK;
}


template <class Logged>
typename Database<Logged>::LookupResult FileDB<Logged>::LookupByIndex(
    int64_t sequence_number, Logged* result) const {
  CHECK_GE(sequence_number, 0);

  util::StatusOr<std::string> hash(HashFromIndex(sequence_number));
  if (!hash.ok()) {
    return this->NOT_FOUND;
  }

  if (result) {
    std::string cert_data;
    CHECK_EQ(cert_storage_->LookupEntry(hash.ValueOrDie(), &cert_data),
             util::Status::OK);

    CHECK(result->ParseFromString(cert_data));
    CHECK_EQ(result->sequence_number(), sequence_number);
    CHECK_EQ(result->Hash(), hash.ValueOrDie());
  }

  return this->LOOKUP_OK;
}


template <class Logged>
typename Database<Logged>::WriteResult FileDB<Logged>::WriteTreeHead_(
    const ct::SignedTreeHead& sth) {
  CHECK_GE(sth.tree_size(), 0);

  // 6 bytes are good enough for some 9000 years.
  std::string timestamp_key =
      Serializer::SerializeUint(sth.timestamp(),
                                FileDB::kTimestampBytesIndexed);
  std::string data;
  CHECK(sth.SerializeToString(&data));

  std::unique_lock<std::mutex> lock(lock_);
  util::Status status(tree_storage_->CreateEntry(timestamp_key, data));
  if (status.CanonicalCode() == util::error::ALREADY_EXISTS) {
    return this->DUPLICATE_TREE_HEAD_TIMESTAMP;
  }
  CHECK_EQ(status, util::Status::OK);

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
int64_t FileDB<Logged>::TreeSize() const {
  std::lock_guard<std::mutex> lock(lock_);

  return dense_entries_.size();
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
  dense_entries_.reserve(hashes.size());

  for (const auto& hash : hashes) {
    std::string cert_data;
    // Read the data; tolerate no errors.
    CHECK_EQ(cert_storage_->LookupEntry(hash, &cert_data), util::Status::OK)
        << "Failed to read entry with hash " << hash;

    Logged logged;
    CHECK(logged.ParseFromString(cert_data))
        << "Failed to parse entry with hash " << hash;
    CHECK(logged.has_sequence_number())
        << "No sequence number for entry with hash " << hash;
    CHECK_GE(logged.sequence_number(), 0)
        << "Entry has a negative sequence number: " << hash;
    CHECK_EQ(logged.Hash(), hash) << "Incorrect digest for entry with hash "
                                  << hash;

    InsertEntryMapping(logged.sequence_number(), hash);
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


template <class Logged>
util::StatusOr<std::string> FileDB<Logged>::HashFromIndex(
    int64_t sequence_number) const {
  CHECK_GE(sequence_number, 0);
  std::lock_guard<std::mutex> lock(lock_);

  if (sequence_number < dense_entries_.size()) {
    return dense_entries_[sequence_number];
  }

  std::map<int64_t, std::string>::const_iterator it(
      sparse_entries_.find(sequence_number));
  if (it != sparse_entries_.end()) {
    return it->second;
  }

  return util::Status(util::error::NOT_FOUND,
                      "no entry found for index " +
                          std::to_string(sequence_number));
}


// This must be called with "lock_" held.
template <class Logged>
void FileDB<Logged>::InsertEntryMapping(int64_t sequence_number,
                                        const std::string& hash) {
  CHECK_GE(sequence_number, dense_entries_.size())
      << "sequence number " << sequence_number
      << " already assigned when inserting hash " << hash;

  if (sequence_number == dense_entries_.size()) {
    // We're optimistic!
    dense_entries_.reserve(dense_entries_.size() + sparse_entries_.size() + 1);

    // It's contiguous, put it back there, and check if we can pull in
    // sparse entries.
    dense_entries_.push_back(hash);

    std::map<int64_t, std::string>::const_iterator it(sparse_entries_.begin());
    while (it != sparse_entries_.end()) {
      if (it->first != dense_entries_.size()) {
        break;
      }

      dense_entries_.emplace_back(it->second);
      it = sparse_entries_.erase(it);
    }
  } else {
    // It's not contiguous, put it with the other sparse entries.
    CHECK(sparse_entries_.insert(make_pair(sequence_number, hash)).second)
        << "sequence number " << sequence_number
        << " already assigned when inserting hash " << hash;
  }
}


#endif  // CERT_TRANS_LOG_FILE_DB_INL_H_
