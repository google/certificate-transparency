/* -*- indent-tabs-mode: nil -*- */
#ifndef CERT_TRANS_LOG_SQLITE_DB_INL_H_
#define CERT_TRANS_LOG_SQLITE_DB_INL_H_

#include "log/sqlite_db.h"

#include <glog/logging.h>
#include <sqlite3.h>

#include "log/sqlite_statement.h"
#include "util/util.h"

namespace {


sqlite3* SQLiteOpen(const std::string& dbfile) {
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
                                   "CREATE TABLE leaves(hash BLOB UNIQUE, "
                                   "entry BLOB, sequence INTEGER UNIQUE)",
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
SQLiteDB<Logged>::SQLiteDB(const std::string& dbfile)
    : db_(SQLiteOpen(dbfile)), tree_size_(0) {
  UpdateTreeSize();
}


template <class Logged>
SQLiteDB<Logged>::~SQLiteDB() {
  CHECK_EQ(SQLITE_OK, sqlite3_close(db_));
}


template <class Logged>
typename Database<Logged>::WriteResult SQLiteDB<Logged>::CreateSequencedEntry_(
    const Logged& logged) {
  std::lock_guard<std::mutex> lock(lock_);

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
    sqlite::Statement s2(db_,
                         "SELECT sequence FROM leaves WHERE sequence = ?");
    s2.BindUInt64(0, logged.sequence_number());
    if (s2.Step() == SQLITE_ROW) {
      return this->SEQUENCE_NUMBER_ALREADY_IN_USE;
    }

    sqlite::Statement s3(db_, "SELECT hash FROM leaves WHERE hash = ?");
    s3.BindBlob(0, hash);
    CHECK_EQ(SQLITE_ROW, s3.Step());
    return this->ENTRY_ALREADY_LOGGED;
  }
  CHECK_EQ(SQLITE_DONE, ret);

  UpdateTreeSize();

  return this->OK;
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::LookupByHash(
    const std::string& hash, Logged* result) const {
  CHECK_NOTNULL(result);

  std::lock_guard<std::mutex> lock(lock_);

  sqlite::Statement statement(db_,
                              "SELECT entry, sequence FROM leaves "
                              "WHERE hash = ?");

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
  }

  return this->LOOKUP_OK;
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::LookupByIndex(
    int64_t sequence_number, Logged* result) const {
  std::lock_guard<std::mutex> lock(lock_);

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

  return this->LOOKUP_OK;
}


template <class Logged>
typename Database<Logged>::WriteResult SQLiteDB<Logged>::WriteTreeHead_(
    const ct::SignedTreeHead& sth) {
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
                         "SELECT timestamp FROM trees "
                         "WHERE timestamp = ?");
    s2.BindUInt64(0, sth.timestamp());
    CHECK_EQ(SQLITE_ROW, s2.Step());
    return this->DUPLICATE_TREE_HEAD_TIMESTAMP;
  }
  CHECK_EQ(SQLITE_DONE, r2);

  // Do not call the callbacks while holding the lock, as they might
  // want to perform some lookups.
  lock.unlock();
  callbacks_.Call(sth);

  return this->OK;
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::LatestTreeHead(
    ct::SignedTreeHead* result) const {
  std::lock_guard<std::mutex> lock(lock_);

  return LatestTreeHeadNoLock(result);
}


template <class Logged>
int64_t SQLiteDB<Logged>::TreeSize() const {
  std::lock_guard<std::mutex> lock(lock_);

  CHECK_GE(tree_size_, 0);
  return tree_size_;
}


template <class Logged>
void SQLiteDB<Logged>::AddNotifySTHCallback(
    const typename Database<Logged>::NotifySTHCallback* callback) {
  std::unique_lock<std::mutex> lock(lock_);

  callbacks_.Add(callback);

  ct::SignedTreeHead sth;
  if (LatestTreeHeadNoLock(&sth) == this->LOOKUP_OK) {
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
void SQLiteDB<Logged>::ForceNotifySTH() {
  std::unique_lock<std::mutex> lock(lock_);

  ct::SignedTreeHead sth;
  const typename Database<Logged>::LookupResult db_result =
      this->LatestTreeHeadNoLock(&sth);
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
typename Database<Logged>::LookupResult
SQLiteDB<Logged>::LatestTreeHeadNoLock(ct::SignedTreeHead* result) const {
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


// Must be called with "lock_" held.
template <class Logged>
void SQLiteDB<Logged>::UpdateTreeSize() {
  CHECK_GE(tree_size_, 0);

  sqlite::Statement statement(
      db_,
      "SELECT sequence FROM leaves WHERE sequence >= ? ORDER BY sequence;");
  statement.BindUInt64(0, tree_size_);

  int ret(statement.Step());
  while (ret == SQLITE_ROW) {
    const sqlite3_uint64 sequence(statement.GetUInt64(0));

    if (sequence != tree_size_) {
      return;
    }

    ++tree_size_;
    ret = statement.Step();
  }
  CHECK_EQ(SQLITE_DONE, ret);
}


#endif  // CERT_TRANS_LOG_SQLITE_DB_INL_H_
