/* -*- indent-tabs-mode: nil -*- */
#include <glog/logging.h>
#include <map>
#include <set>
#include <stdint.h>
#include <utility>  // for std::pair
#include <vector>

#include "log/file_db.h"
#include "log/file_storage.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"

using ct::SignedCertificateTimestamp;
using ct::LoggablePB;
using ct::SignedTreeHead;
using std::string;

const size_t FileDB::kTimestampBytesIndexed = 6;

FileDB::FileDB(FileStorage *log_storage, FileStorage *tree_storage)
    : log_storage_(log_storage),
      tree_storage_(tree_storage),
      latest_tree_timestamp_(0) {
  BuildIndex();
}

FileDB::~FileDB() {
  delete log_storage_;
  delete tree_storage_;
}

Database::WriteResult FileDB::CreatePendingEntry_(const Loggable &loggable) {
  if (pending_hashes_.find(loggable.hash()) != pending_hashes_.end())
    return DUPLICATE_HASH;

  LoggablePB loggable_pb;
  CHECK(loggable.SerializeToString(loggable_pb.mutable_data()));
  if (loggable.has_sequence_number())
    loggable_pb.set_sequence_number(loggable.sequence_number());
  loggable_pb.set_hash(loggable.hash());

  string data;
  CHECK(loggable_pb.SerializeToString(&data));

  // Try to create.
  FileStorage::FileStorageResult result =
      log_storage_->CreateEntry(loggable.hash(), data);
  if (result == FileStorage::ENTRY_ALREADY_EXISTS)
    return DUPLICATE_HASH;
  assert(result == FileStorage::OK);
  pending_hashes_.insert(loggable.hash());
  return OK;
}

std::set<string> FileDB::PendingHashes() const {
  return pending_hashes_;
}

Database::WriteResult FileDB::AssignSequenceNumber(const string &pending_hash,
                                                   uint64_t sequence_number) {
  std::set<string>::iterator pending_it =
      pending_hashes_.find(pending_hash);
  if (pending_it == pending_hashes_.end()) {
    // Caller should have ensured we don't get here...
    if (log_storage_->LookupEntry(pending_hash, NULL) == FileStorage::OK)
      return ENTRY_ALREADY_LOGGED;
    return ENTRY_NOT_FOUND;
  }

  if (sequence_map_.find(sequence_number) != sequence_map_.end())
    return SEQUENCE_NUMBER_ALREADY_IN_USE;

  string data;
  FileStorage::FileStorageResult result =
      log_storage_->LookupEntry(pending_hash, &data);
  assert(result == FileStorage::OK);

  LoggablePB loggable;
  CHECK(loggable.ParseFromString(data));

  assert(!loggable.has_sequence_number());
  loggable.set_sequence_number(sequence_number);
  loggable.SerializeToString(&data);
  result = log_storage_->UpdateEntry(pending_hash, data);
  assert(result == FileStorage::OK);

  pending_hashes_.erase(pending_it);
  sequence_map_.insert(std::pair<uint64_t, string>(sequence_number,
                                                   pending_hash));
  return OK;
}

Database::LookupResult FileDB::LookupByHash(const string &hash,
                                            Loggable *result) const {
  string data;
  FileStorage::FileStorageResult db_result =
      log_storage_->LookupEntry(hash, &data);
  if (db_result == FileStorage::NOT_FOUND)
    return NOT_FOUND;
  assert(db_result == FileStorage::OK);

  CHECK(result != NULL);

  LoggablePB loggable_pb;
  CHECK(loggable_pb.ParseFromString(data));
  CHECK_EQ(loggable_pb.hash(), hash);

  CHECK(result->ParseFromString(loggable_pb.data()));

  if (loggable_pb.has_sequence_number())
    result->set_sequence_number(loggable_pb.sequence_number());
  result->set_hash(hash);

  return LOOKUP_OK;
}

Database::LookupResult FileDB::LookupByIndex(uint64_t sequence_number,
                                             Loggable *result) const {
  std::map<uint64_t, string>::const_iterator it =
      sequence_map_.find(sequence_number);
  if (it == sequence_map_.end())
    return NOT_FOUND;

  if (result != NULL) {
    string data;
    FileStorage::FileStorageResult db_result =
        log_storage_->LookupEntry(it->second, &data);
    assert(db_result == FileStorage::OK);

    LoggablePB loggable_pb;
    CHECK(loggable_pb.ParseFromString(data));
    CHECK_EQ(loggable_pb.sequence_number(), sequence_number);

    CHECK(result->ParseFromString(loggable_pb.data()));

    result->set_sequence_number(sequence_number);
    result->set_hash(loggable_pb.hash());
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
  pending_hashes_ = log_storage_->Scan();
  if (pending_hashes_.empty())
    return;
  // Now read the entries: remove those that have a sequence number
  // from the set of pending entries and add them to the index.
  std::set<string>::iterator it = pending_hashes_.begin();
  do {
    // Increment before any erase operations.
    std::set<string>::iterator it2 = it++;
    string data;
    // Read the data; tolerate no errors.
    FileStorage::FileStorageResult result = log_storage_->LookupEntry(*it2,
                                                                      &data);
    if (result != FileStorage::OK)
      abort();
    LoggablePB loggable;
    if (!loggable.ParseFromString(data))
      abort();
    if (loggable.has_sequence_number()) {
      sequence_map_.insert(
          std::pair<uint64_t, string>(loggable.sequence_number(), *it2));
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
