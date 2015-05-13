#ifndef CERT_TRANS_LOG_LEVELDB_DB_INL_H_
#define CERT_TRANS_LOG_LEVELDB_DB_INL_H_

#include "log/leveldb_db.h"

#include <glog/logging.h>
#include <map>
#include <stdint.h>
#include <string>

#include "proto/ct.pb.h"
#include "proto/serializer.h"
#include "monitoring/monitoring.h"
#include "monitoring/latency.h"
#include "util/util.h"

DEFINE_int32(leveldb_max_open_files, 0,
             "number of open files that can be used by leveldb");
DEFINE_int32(leveldb_bloom_filter_bits_per_key, 0,
             "number of open files that can be used by leveldb");

namespace {


static cert_trans::Latency<std::chrono::milliseconds, std::string>
    latency_by_op_ms("leveldb_latency_by_operation_ms", "operation",
                     "Database latency in ms broken out by operation.");


const char kMetaNodeIdKey[] = "metadata";
const char kEntryPrefix[] = "entry-";
const char kTreeHeadPrefix[] = "sth-";
const char kMetaPrefix[] = "meta-";


#ifdef HAVE_LEVELDB_FILTER_POLICY_H
std::unique_ptr<const leveldb::FilterPolicy> BuildFilterPolicy() {
  std::unique_ptr<const leveldb::FilterPolicy> retval;

  if (FLAGS_leveldb_bloom_filter_bits_per_key > 0) {
    retval.reset(CHECK_NOTNULL(leveldb::NewBloomFilterPolicy(
        FLAGS_leveldb_bloom_filter_bits_per_key)));
  }

  return retval;
}
#endif


// WARNING: Do NOT change the type of "index" from int64_t, or you'll
// break existing databases!
std::string IndexToKey(int64_t index) {
  const char nibble[] = "0123456789abcdef";
  std::string index_str(sizeof(index) * 2, nibble[0]);
  for (int i = sizeof(index) * 2; i > 0 && index > 0; --i) {
    index_str[i - 1] = nibble[index & 0xf];
    index = index >> 4;
  }

  return kEntryPrefix + index_str;
}


int64_t KeyToIndex(leveldb::Slice key) {
  CHECK(key.starts_with(kEntryPrefix));
  key.remove_prefix(strlen(kEntryPrefix));
  const std::string index_str(util::BinaryString(key.ToString()));

  int64_t index(0);
  CHECK_EQ(index_str.size(), sizeof(index));
  for (int i = 0; i < sizeof(index); ++i) {
    index = (index << 8) + index_str[i];
  }

  return index;
}


}  // namespace


template <class Logged>
const size_t LevelDB<Logged>::kTimestampBytesIndexed = 6;


template <class Logged>
LevelDB<Logged>::LevelDB(const std::string& dbfile)
    :
#ifdef HAVE_LEVELDB_FILTER_POLICY_H
      filter_policy_(BuildFilterPolicy()),
#endif
      contiguous_size_(0),
      latest_tree_timestamp_(0) {
  LOG(INFO) << "Opening " << dbfile;
  cert_trans::ScopedLatency latency(latency_by_op_ms.GetScopedLatency("open"));
  leveldb::Options options;
  options.create_if_missing = true;
  if (FLAGS_leveldb_max_open_files > 0) {
    options.max_open_files = FLAGS_leveldb_max_open_files;
  }
#ifdef HAVE_LEVELDB_FILTER_POLICY_H
  options.filter_policy = filter_policy_.get();
#else
  CHECK_EQ(FLAGS_leveldb_bloom_filter_bits_per_key, 0)
      << "this version of leveldb does not have bloom filter support";
#endif
  leveldb::DB* db;
  leveldb::Status status(leveldb::DB::Open(options, dbfile, &db));
  CHECK(status.ok()) << status.ToString();
  db_.reset(db);

  BuildIndex();
}


template <class Logged>
typename Database<Logged>::WriteResult LevelDB<Logged>::CreateSequencedEntry_(
    const Logged& logged) {
  CHECK(logged.has_sequence_number());
  CHECK_GE(logged.sequence_number(), 0);
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("create_sequenced_entry"));

  std::unique_lock<std::mutex> lock(lock_);

  std::string data;
  CHECK(logged.SerializeToString(&data));

  const std::string key(IndexToKey(logged.sequence_number()));

  std::string existing_data;
  leveldb::Status status(
      db_->Get(leveldb::ReadOptions(), key, &existing_data));
  if (status.IsNotFound()) {
    status = db_->Put(leveldb::WriteOptions(), key, data);
    CHECK(status.ok()) << "Failed to write sequenced entry (seq: "
                       << logged.sequence_number()
                       << "): " << status.ToString();
  } else {
    if (existing_data == data) {
      return this->OK;
    }
    return this->SEQUENCE_NUMBER_ALREADY_IN_USE;
  }

  InsertEntryMapping(logged.sequence_number(), logged.Hash());

  return this->OK;
}


template <class Logged>
typename Database<Logged>::LookupResult LevelDB<Logged>::LookupByHash(
    const std::string& hash, Logged* result) const {
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("lookup_by_hash"));

  std::unique_lock<std::mutex> lock(lock_);

  auto i(id_by_hash_.find(hash));
  if (i == id_by_hash_.end()) {
    return this->NOT_FOUND;
  }

  std::string cert_data;
  const leveldb::Status status(
      db_->Get(leveldb::ReadOptions(), IndexToKey(i->second), &cert_data));
  if (status.IsNotFound()) {
    return this->NOT_FOUND;
  }
  CHECK(status.ok()) << "Failed to get entry by hash(" << util::HexString(hash)
                     << "): " << status.ToString();

  Logged logged;
  CHECK(logged.ParseFromString(cert_data));
  CHECK_EQ(logged.Hash(), hash);

  if (result) {
    logged.Swap(result);
  }

  return this->LOOKUP_OK;
}


template <class Logged>
typename Database<Logged>::LookupResult LevelDB<Logged>::LookupByIndex(
    int64_t sequence_number, Logged* result) const {
  CHECK_GE(sequence_number, 0);
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("lookup_by_index"));

  std::string cert_data;
  leveldb::Status status(db_->Get(leveldb::ReadOptions(),
                                  IndexToKey(sequence_number), &cert_data));
  if (status.IsNotFound()) {
    return this->NOT_FOUND;
  }
  CHECK(status.ok()) << "Failed to get entry for sequence number "
                     << sequence_number;

  if (result) {
    CHECK(result->ParseFromString(cert_data));
    CHECK_EQ(result->sequence_number(), sequence_number);
  }

  return this->LOOKUP_OK;
}


template <class Logged>
typename Database<Logged>::WriteResult LevelDB<Logged>::WriteTreeHead_(
    const ct::SignedTreeHead& sth) {
  CHECK_GE(sth.tree_size(), 0);
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("write_tree_head"));

  // 6 bytes are good enough for some 9000 years.
  std::string timestamp_key =
      Serializer::SerializeUint(sth.timestamp(),
                                LevelDB::kTimestampBytesIndexed);
  std::string data;
  CHECK(sth.SerializeToString(&data));

  std::unique_lock<std::mutex> lock(lock_);
  std::string existing_data;
  leveldb::Status status(db_->Get(leveldb::ReadOptions(),
                                  kTreeHeadPrefix + timestamp_key,
                                  &existing_data));
  if (status.ok()) {
    if (existing_data == data) {
      return this->OK;
    }
    return this->DUPLICATE_TREE_HEAD_TIMESTAMP;
  }

  status =
      db_->Put(leveldb::WriteOptions(), kTreeHeadPrefix + timestamp_key, data);
  CHECK(status.ok()) << "Failed to write tree head (" << timestamp_key
                     << "): " << status.ToString();

  if (sth.timestamp() > latest_tree_timestamp_) {
    latest_tree_timestamp_ = sth.timestamp();
    latest_timestamp_key_ = timestamp_key;
  }

  lock.unlock();
  callbacks_.Call(sth);

  return this->OK;
}


template <class Logged>
typename Database<Logged>::LookupResult LevelDB<Logged>::LatestTreeHead(
    ct::SignedTreeHead* result) const {
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("latest_tree_head"));
  std::lock_guard<std::mutex> lock(lock_);

  return LatestTreeHeadNoLock(result);
}


template <class Logged>
int64_t LevelDB<Logged>::TreeSize() const {
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("tree_size"));
  std::lock_guard<std::mutex> lock(lock_);

  return contiguous_size_;
}


template <class Logged>
void LevelDB<Logged>::AddNotifySTHCallback(
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
void LevelDB<Logged>::RemoveNotifySTHCallback(
    const typename Database<Logged>::NotifySTHCallback* callback) {
  std::lock_guard<std::mutex> lock(lock_);

  callbacks_.Remove(callback);
}


template <class Logged>
void LevelDB<Logged>::InitializeNode(const std::string& node_id) {
  CHECK(!node_id.empty());
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("initialize_node"));
  std::unique_lock<std::mutex> lock(lock_);
  std::string existing_id;
  leveldb::Status status(db_->Get(leveldb::ReadOptions(),
                                  std::string(kMetaPrefix) + kMetaNodeIdKey,
                                  &existing_id));
  if (!status.IsNotFound()) {
    LOG(FATAL) << "Attempting to initialize DB beloging to node with node_id: "
               << existing_id;
  }
  status = db_->Put(leveldb::WriteOptions(),
                    std::string(kMetaPrefix) + kMetaNodeIdKey, node_id);
  CHECK(status.ok()) << "Failed to store NodeId: " << status.ToString();
}


template <class Logged>
typename Database<Logged>::LookupResult LevelDB<Logged>::NodeId(
    std::string* node_id) {
  CHECK_NOTNULL(node_id);
  if (!db_->Get(leveldb::ReadOptions(),
                std::string(kMetaPrefix) + kMetaNodeIdKey, node_id)
           .ok()) {
    return this->NOT_FOUND;
  }
  return this->LOOKUP_OK;
}


template <class Logged>
void LevelDB<Logged>::BuildIndex() {
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("build_index"));
  // Technically, this should only be called from the constructor, so
  // this should not be necessarily, but just to be sure...
  std::lock_guard<std::mutex> lock(lock_);

  leveldb::ReadOptions options;
  options.fill_cache = false;
  std::unique_ptr<leveldb::Iterator> it(db_->NewIterator(options));
  CHECK(it);
  it->Seek(kEntryPrefix);

  for (; it->Valid() && it->key().starts_with(kEntryPrefix); it->Next()) {
    const int64_t seq(KeyToIndex(it->key()));
    Logged logged;
    CHECK(logged.ParseFromString(it->value().ToString()))
        << "Failed to parse entry with sequence number " << seq;
    CHECK(logged.has_sequence_number())
        << "No sequence number for entry with sequence number " << seq;
    CHECK_EQ(logged.sequence_number(), seq)
        << "Entry has unexpected sequence_number: " << seq;

    InsertEntryMapping(logged.sequence_number(), logged.Hash());
  }

  // Now read the STH entries.
  it->Seek(kTreeHeadPrefix);
  for (; it->Valid() && it->key().starts_with(kTreeHeadPrefix); it->Next()) {
    leveldb::Slice key_slice(it->key());
    key_slice.remove_prefix(strlen(kTreeHeadPrefix));
    latest_timestamp_key_ = key_slice.ToString();
    CHECK_EQ(Deserializer::OK,
             Deserializer::DeserializeUint<uint64_t>(
                 latest_timestamp_key_, LevelDB::kTimestampBytesIndexed,
                 &latest_tree_timestamp_));
  }
}


template <class Logged>
typename Database<Logged>::LookupResult LevelDB<Logged>::LatestTreeHeadNoLock(
    ct::SignedTreeHead* result) const {
  if (latest_tree_timestamp_ == 0) {
    return this->NOT_FOUND;
  }

  std::string tree_data;
  leveldb::Status status(db_->Get(leveldb::ReadOptions(),
                                  kTreeHeadPrefix + latest_timestamp_key_,
                                  &tree_data));
  CHECK(status.ok()) << "Failed to read latest tree head: "
                     << status.ToString();

  CHECK(result->ParseFromString(tree_data));
  CHECK_EQ(result->timestamp(), latest_tree_timestamp_);

  return this->LOOKUP_OK;
}


// This must be called with "lock_" held.
template <class Logged>
void LevelDB<Logged>::InsertEntryMapping(int64_t sequence_number,
                                         const std::string& hash) {
  if (!id_by_hash_.insert(std::make_pair(hash, sequence_number)).second) {
    // This is a duplicate hash under a new sequence number.
    // Make sure we track the entry with the lowest sequence number:
    id_by_hash_[hash] = std::min(id_by_hash_[hash], sequence_number);
  }
  if (sequence_number == contiguous_size_) {
    ++contiguous_size_;
    for (auto i = sparse_entries_.find(contiguous_size_);
         i != sparse_entries_.end() && *i == contiguous_size_;) {
      ++contiguous_size_;
      i = sparse_entries_.erase(i);
    }
  } else {
    // It's not contiguous, put it with the other sparse entries.
    CHECK(sparse_entries_.insert(sequence_number).second)
        << "sequence number " << sequence_number << " already assigned.";
  }
}


#endif  // CERT_TRANS_LOG_LEVELDB_DB_INL_H_
