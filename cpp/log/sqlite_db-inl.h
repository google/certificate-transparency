/* -*- indent-tabs-mode: nil -*- */
#ifndef CERT_TRANS_LOG_SQLITE_DB_INL_H_
#define CERT_TRANS_LOG_SQLITE_DB_INL_H_

#include "log/sqlite_db.h"

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <sqlite3.h>

#include "log/sqlite_statement.h"
#include "monitoring/monitoring.h"
#include "monitoring/latency.h"
#include "util/util.h"

// Several of these flags pass their value directly through to SQLite PRAGMA
// statements, see the SQLite documentation
// (https://www.sqlite.org/pragma.html) for a description of the various
// values available and the implications they have.

// TODO(pphaneuf): For now, just a flag, but ideally, when adding a
// new node, it would do an initial load of its local database with
// "synchronous" set to OFF, then put it back before starting normal
// operation.
DEFINE_string(sqlite_synchronous_mode, "FULL",
              "Which SQLite synchronous option to use, see SQLite pragma "
              "documentation for details.");

DEFINE_string(sqlite_journal_mode, "WAL",
              "Which SQLite journal_mode option to use, see SQLite pragma "
              "documentation for defails.");

DEFINE_int32(sqlite_cache_size, 100000,
             "Number of 1KB btree pages to keep in memory.");

DEFINE_bool(sqlite_batch_into_transactions, true,
            "Whether to batch operations into transactions behind the "
            "scenes.");
DEFINE_int32(sqlite_transaction_batch_size, 400,
             "Max number of operations to batch into one transaction.");


namespace {


static cert_trans::Latency<std::chrono::milliseconds, std::string>
    latency_by_op_ms("sqlitedb_latency_by_operation_ms", "operation",
                     "Database latency in ms broken out by operation");


sqlite3* SQLiteOpen(const std::string& dbfile) {
  cert_trans::ScopedLatency scoped_latency(
      latency_by_op_ms.GetScopedLatency("open"));
  sqlite3* retval;

  const int ret(
      sqlite3_open_v2(dbfile.c_str(), &retval, SQLITE_OPEN_READWRITE, NULL));
  if (ret == SQLITE_OK) {
    return retval;
  }
  CHECK_EQ(SQLITE_CANTOPEN, ret);

  // We have to close and reopen to avoid memory leaks.
  CHECK_EQ(SQLITE_OK, sqlite3_close(retval));
  retval = nullptr;

  CHECK_EQ(SQLITE_OK,
           sqlite3_open_v2(dbfile.c_str(), &retval,
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                           nullptr));
  CHECK_EQ(SQLITE_OK, sqlite3_exec(retval,
                                   "CREATE TABLE leaves(hash BLOB, "
                                   "entry BLOB, sequence INTEGER UNIQUE)",
                                   nullptr, nullptr, nullptr));
  CHECK_EQ(SQLITE_OK, sqlite3_exec(retval,
                                   "CREATE INDEX leaves_hash_idx ON "
                                   "leaves(hash)",
                                   nullptr, nullptr, nullptr));
  CHECK_EQ(SQLITE_OK,
           sqlite3_exec(
               retval,
               "CREATE TABLE trees(sth BLOB UNIQUE, timestamp INTEGER UNIQUE)",
               nullptr, nullptr, nullptr));

  CHECK_EQ(SQLITE_OK,
           sqlite3_exec(retval, "CREATE TABLE node(node_id BLOB UNIQUE)",
                        nullptr, nullptr, nullptr));

  LOG(INFO) << "New SQLite database created in " << dbfile;

  return retval;
}


}  // namespace


template <class Logged>
class SQLiteDB<Logged>::Iterator : public Database<Logged>::Iterator {
 public:
  Iterator(const SQLiteDB<Logged>* db, int64_t start_index)
      : db_(CHECK_NOTNULL(db)), next_index_(start_index) {
    CHECK_GE(next_index_, 0);
  }

  bool GetNextEntry(Logged* entry) override {
    CHECK_NOTNULL(entry);
    std::unique_lock<std::mutex> lock(db_->lock_);
    if (next_index_ < db_->tree_size_) {
      CHECK_EQ(db_->LookupByIndex(lock, next_index_, entry), db_->LOOKUP_OK);
      ++next_index_;
      return true;
    }

    const bool retval(db_->LookupNextIndex(lock, next_index_, entry) ==
                      db_->LOOKUP_OK);
    if (retval) {
      next_index_ = entry->sequence_number() + 1;
    }

    return retval;
  }

 private:
  const SQLiteDB<Logged>* const db_;
  int64_t next_index_;
};


template <class Logged>
SQLiteDB<Logged>::SQLiteDB(const std::string& dbfile)
    : db_(SQLiteOpen(dbfile)),
      tree_size_(0),
      transaction_size_(0),
      in_transaction_(false) {
  std::unique_lock<std::mutex> lock(lock_);
  {
    std::ostringstream oss;
    oss << "PRAGMA synchronous = " << FLAGS_sqlite_synchronous_mode;
    sqlite::Statement statement(db_, oss.str().c_str());
    CHECK_EQ(SQLITE_DONE, statement.Step());
    LOG(WARNING) << "SQLite \"synchronous\" pragma set to "
                 << FLAGS_sqlite_synchronous_mode;
    if (FLAGS_sqlite_batch_into_transactions) {
      LOG(WARNING) << "SQLite running with batched transactions, you should "
                   << "set sqlite_synchronous_mode = FULL !";
    }
  }

  {
    std::ostringstream oss;
    oss << "PRAGMA journal_mode = " << FLAGS_sqlite_journal_mode;
    sqlite::Statement statement(db_, oss.str().c_str());
    CHECK_EQ(SQLITE_ROW, statement.Step());
    std::string mode;
    statement.GetBlob(0, &mode);
    CHECK_STRCASEEQ(mode.c_str(), FLAGS_sqlite_journal_mode.c_str());
    CHECK_EQ(SQLITE_DONE, statement.Step());
  }

  {
    std::ostringstream oss;
    oss << "PRAGMA cache_size = " << FLAGS_sqlite_cache_size;
    sqlite::Statement statement(db_, oss.str().c_str());
    CHECK_EQ(SQLITE_DONE, statement.Step());
  }

  BeginTransaction(lock);
}


template <class Logged>
SQLiteDB<Logged>::~SQLiteDB() {
  CHECK_EQ(SQLITE_OK, sqlite3_close(db_));
}


template <class Logged>
typename Database<Logged>::WriteResult SQLiteDB<Logged>::CreateSequencedEntry_(
    const Logged& logged) {
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("create_sequenced_entry"));
  std::unique_lock<std::mutex> lock(lock_);

  MaybeStartNewTransaction(lock);

  sqlite::Statement statement(db_,
                              "INSERT INTO leaves(hash, entry, sequence) "
                              "VALUES(?, ?, ?)");
  const std::string hash(logged.Hash());
  statement.BindBlob(0, hash);

  std::string data;
  CHECK(logged.SerializeForDatabase(&data));
  statement.BindBlob(1, data);

  CHECK(logged.has_sequence_number());
  statement.BindUInt64(2, logged.sequence_number());

  int ret = statement.Step();
  if (ret == SQLITE_CONSTRAINT) {
    // Check whether we're trying to store a hash/sequence pair which already
    // exists - if it's identical we'll return OK as it could be the fetcher.
    sqlite::Statement s2(
        db_, "SELECT sequence, hash FROM leaves WHERE sequence = ?");
    s2.BindUInt64(0, logged.sequence_number());
    if (s2.Step() == SQLITE_ROW) {
      std::string existing_hash;
      s2.GetBlob(1, &existing_hash);

      if (logged.sequence_number() == tree_size_) {
        ++tree_size_;
      }

      if (hash == existing_hash) {
        return this->OK;
      }
    }
    return this->SEQUENCE_NUMBER_ALREADY_IN_USE;
  }
  CHECK_EQ(SQLITE_DONE, ret);

  if (logged.sequence_number() == tree_size_) {
    ++tree_size_;
  }

  return this->OK;
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::LookupByHash(
    const std::string& hash, Logged* result) const {
  CHECK_NOTNULL(result);
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("lookup_by_hash"));

  std::lock_guard<std::mutex> lock(lock_);

  sqlite::Statement statement(db_,
                              "SELECT entry, sequence FROM leaves "
                              "WHERE hash = ? ORDER BY sequence LIMIT 1");

  statement.BindBlob(0, hash);

  int ret = statement.Step();
  if (ret == SQLITE_DONE) {
    return this->NOT_FOUND;
  }
  CHECK_EQ(SQLITE_ROW, ret);

  std::string data;
  statement.GetBlob(0, &data);
  CHECK(result->ParseFromDatabase(data));

  if (statement.GetType(1) == SQLITE_NULL) {
    result->clear_sequence_number();
  } else {
    result->set_sequence_number(statement.GetUInt64(1));
    if (result->sequence_number() == tree_size_) {
      ++tree_size_;
    }
  }

  return this->LOOKUP_OK;
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::LookupByIndex(
    int64_t sequence_number, Logged* result) const {
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("lookup_by_index"));
  std::unique_lock<std::mutex> lock(lock_);

  return LookupByIndex(lock, sequence_number, result);
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::LookupByIndex(
    const std::unique_lock<std::mutex>& lock, int64_t sequence_number,
    Logged* result) const {
  CHECK(lock.owns_lock());
  CHECK_GE(sequence_number, 0);
  CHECK_NOTNULL(result);
  sqlite::Statement statement(db_,
                              "SELECT entry, hash FROM leaves "
                              "WHERE sequence = ?");
  statement.BindUInt64(0, sequence_number);
  int ret = statement.Step();
  if (ret == SQLITE_DONE) {
    return this->NOT_FOUND;
  }

  std::string data;
  statement.GetBlob(0, &data);
  CHECK(result->ParseFromDatabase(data));

  std::string hash;
  statement.GetBlob(1, &hash);

  CHECK_EQ(result->Hash(), hash);

  result->set_sequence_number(sequence_number);
  if (result->sequence_number() == tree_size_) {
    ++tree_size_;
  }

  return this->LOOKUP_OK;
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::LookupNextIndex(
    const std::unique_lock<std::mutex>& lock, int64_t sequence_number,
    Logged* result) const {
  CHECK(lock.owns_lock());
  CHECK_GE(sequence_number, 0);
  CHECK_NOTNULL(result);
  sqlite::Statement statement(db_,
                              "SELECT entry, hash, sequence FROM leaves "
                              "WHERE sequence >= ? ORDER BY sequence");
  statement.BindUInt64(0, sequence_number);
  if (statement.Step() == SQLITE_DONE) {
    return this->NOT_FOUND;
  }

  std::string data;
  statement.GetBlob(0, &data);
  CHECK(result->ParseFromDatabase(data));

  std::string hash;
  statement.GetBlob(1, &hash);

  CHECK_EQ(result->Hash(), hash);

  result->set_sequence_number(statement.GetUInt64(2));
  if (result->sequence_number() == tree_size_) {
    ++tree_size_;
  }

  return this->LOOKUP_OK;
}


template <class Logged>
std::unique_ptr<typename Database<Logged>::Iterator>
SQLiteDB<Logged>::ScanEntries(int64_t start_index) const {
  return std::unique_ptr<Iterator>(new Iterator(this, start_index));
}


template <class Logged>
typename Database<Logged>::WriteResult SQLiteDB<Logged>::WriteTreeHead_(
    const ct::SignedTreeHead& sth) {
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("write_tree_head"));
  std::unique_lock<std::mutex> lock(lock_);

  sqlite::Statement statement(db_,
                              "INSERT INTO trees(timestamp, sth) "
                              "VALUES(?, ?)");
  statement.BindUInt64(0, sth.timestamp());

  std::string sth_data;
  CHECK(sth.SerializeToString(&sth_data));
  statement.BindBlob(1, sth_data);

  int r2 = statement.Step();
  if (r2 == SQLITE_CONSTRAINT) {
    sqlite::Statement s2(db_,
                         "SELECT timestamp,sth FROM trees "
                         "WHERE timestamp = ?");
    s2.BindUInt64(0, sth.timestamp());
    CHECK_EQ(SQLITE_ROW, s2.Step());
    std::string existing_sth_data;
    s2.GetBlob(1, &existing_sth_data);
    if (existing_sth_data == sth_data) {
      LOG(WARNING) << "Attempted to store indentical STH in DB.";
      return this->OK;
    }
    return this->DUPLICATE_TREE_HEAD_TIMESTAMP;
  }
  CHECK_EQ(SQLITE_DONE, r2);

  EndTransaction(lock);
  BeginTransaction(lock);

  // Do not call the callbacks while holding the lock, as they might
  // want to perform some lookups.
  lock.unlock();
  callbacks_.Call(sth);

  return this->OK;
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::LatestTreeHead(
    ct::SignedTreeHead* result) const {
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("latest_tree_head"));
  std::unique_lock<std::mutex> lock(lock_);

  return LatestTreeHeadNoLock(lock, result);
}


template <class Logged>
int64_t SQLiteDB<Logged>::TreeSize() const {
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("tree_size"));
  std::unique_lock<std::mutex> lock(lock_);

  CHECK_GE(tree_size_, 0);
  sqlite::Statement statement(
      db_,
      "SELECT sequence FROM leaves WHERE sequence >= ? ORDER BY sequence");
  statement.BindUInt64(0, tree_size_);

  int ret(statement.Step());
  while (ret == SQLITE_ROW) {
    const sqlite3_uint64 sequence(statement.GetUInt64(0));

    if (sequence != static_cast<uint64_t>(tree_size_)) {
      return tree_size_;
    }

    ++tree_size_;
    ret = statement.Step();
  }
  CHECK_EQ(SQLITE_DONE, ret);

  return tree_size_;
}


template <class Logged>
void SQLiteDB<Logged>::AddNotifySTHCallback(
    const typename Database<Logged>::NotifySTHCallback* callback) {
  std::unique_lock<std::mutex> lock(lock_);

  callbacks_.Add(callback);

  ct::SignedTreeHead sth;
  if (LatestTreeHeadNoLock(lock, &sth) == this->LOOKUP_OK) {
    // Do not call the callback while holding the lock, as they might
    // want to perform some lookups.
    lock.unlock();
    (*callback)(sth);
  }
}


template <class Logged>
void SQLiteDB<Logged>::RemoveNotifySTHCallback(
    const typename Database<Logged>::NotifySTHCallback* callback) {
  std::lock_guard<std::mutex> lock(lock_);

  callbacks_.Remove(callback);
}


template <class Logged>
void SQLiteDB<Logged>::InitializeNode(const std::string& node_id) {
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("initialize_node"));
  CHECK(!node_id.empty());
  std::unique_lock<std::mutex> lock(lock_);
  std::string existing_id;
  if (NodeId(lock, &existing_id) != this->NOT_FOUND) {
    LOG(FATAL) << "Attempting to initialize DB beloging to node with node_id: "
               << existing_id;
  }
  sqlite::Statement statement(db_, "INSERT INTO node(node_id) VALUES(?)");
  statement.BindBlob(0, node_id);

  const int result(statement.Step());
  CHECK_EQ(SQLITE_DONE, result);
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::NodeId(
    std::string* node_id) {
  std::unique_lock<std::mutex> lock(lock_);
  return NodeId(lock, CHECK_NOTNULL(node_id));
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::NodeId(
    const std::unique_lock<std::mutex>& lock, std::string* node_id) {
  cert_trans::ScopedLatency latency(
      latency_by_op_ms.GetScopedLatency("set_node_id"));
  CHECK(lock.owns_lock());
  CHECK_NOTNULL(node_id);
  sqlite::Statement statement(db_, "SELECT node_id FROM node");

  int result(statement.Step());
  if (result == SQLITE_DONE) {
    return this->NOT_FOUND;
  }
  CHECK_EQ(SQLITE_ROW, result);

  statement.GetBlob(0, node_id);
  result = statement.Step();
  CHECK_EQ(SQLITE_DONE, result);  // There can only be one!
  return this->LOOKUP_OK;
}


template <class Logged>
void SQLiteDB<Logged>::BeginTransaction(
    const std::unique_lock<std::mutex>& lock) {
  CHECK(lock.owns_lock());
  if (FLAGS_sqlite_batch_into_transactions) {
    CHECK_EQ(0, transaction_size_);
    CHECK(!in_transaction_);
    VLOG(1) << "Beginning new transaction.";
    sqlite::Statement s(db_, "BEGIN TRANSACTION");
    CHECK_EQ(SQLITE_DONE, s.Step());
    in_transaction_ = true;
  }
}


template <class Logged>
void SQLiteDB<Logged>::EndTransaction(
    const std::unique_lock<std::mutex>& lock) {
  CHECK(lock.owns_lock());
  if (FLAGS_sqlite_batch_into_transactions) {
    CHECK(in_transaction_);
    VLOG(1) << "Committing transaction.";
    {
      sqlite::Statement s(db_, "END TRANSACTION");
      CHECK_EQ(SQLITE_DONE, s.Step());
    }
    {
      sqlite::Statement s(db_, "PRAGMA wal_checkpoint(TRUNCATE)");
      CHECK_EQ(SQLITE_ROW, s.Step());
      CHECK_EQ(SQLITE_DONE, s.Step());
    }

    transaction_size_ = 0;
    in_transaction_ = false;
  }
}


template <class Logged>
void SQLiteDB<Logged>::MaybeStartNewTransaction(
    const std::unique_lock<std::mutex>& lock) {
  CHECK(lock.owns_lock());
  if (FLAGS_sqlite_batch_into_transactions &&
      transaction_size_ >= FLAGS_sqlite_transaction_batch_size) {
    VLOG(1) << "Rolling over into new transaction.";
    EndTransaction(lock);
    BeginTransaction(lock);
  }
  ++transaction_size_;
}


template <class Logged>
void SQLiteDB<Logged>::ForceNotifySTH() {
  std::unique_lock<std::mutex> lock(lock_);

  ct::SignedTreeHead sth;
  const typename Database<Logged>::LookupResult db_result =
      this->LatestTreeHeadNoLock(lock, &sth);
  if (db_result == Database<Logged>::NOT_FOUND) {
    return;
  }

  CHECK(db_result == Database<Logged>::LOOKUP_OK);

  // Do not call the callbacks while holding the lock, as they might
  // want to perform some lookups.
  lock.unlock();
  callbacks_.Call(sth);
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::LatestTreeHeadNoLock(
    const std::unique_lock<std::mutex>& lock,
    ct::SignedTreeHead* result) const {
  CHECK(lock.owns_lock());
  sqlite::Statement statement(db_,
                              "SELECT sth FROM trees WHERE timestamp IN "
                              "(SELECT MAX(timestamp) FROM trees)");

  int ret = statement.Step();
  if (ret == SQLITE_DONE) {
    return this->NOT_FOUND;
  }
  CHECK_EQ(SQLITE_ROW, ret);

  std::string sth;
  statement.GetBlob(0, &sth);
  CHECK(result->ParseFromString(sth));

  return this->LOOKUP_OK;
}


#endif  // CERT_TRANS_LOG_SQLITE_DB_INL_H_
