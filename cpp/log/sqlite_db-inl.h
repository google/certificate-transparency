/* -*- indent-tabs-mode: nil -*- */
#ifndef CERT_TRANS_LOG_SQLITE_DB_INL_H_
#define CERT_TRANS_LOG_SQLITE_DB_INL_H_

#include "log/sqlite_db.h"

#include <glog/logging.h>
#include <sqlite3.h>

#include "log/sqlite_statement.h"
#include "util/util.h"


template <class Logged>
SQLiteDB<Logged>::SQLiteDB(const std::string& dbfile)
    : db_(NULL) {
  int ret = sqlite3_open_v2(dbfile.c_str(), &db_, SQLITE_OPEN_READWRITE, NULL);
  if (ret == SQLITE_OK) {
    return;
  }
  CHECK_EQ(SQLITE_CANTOPEN, ret);

  // We have to close and reopen to avoid memory leaks.
  CHECK_EQ(SQLITE_OK, sqlite3_close(db_));
  db_ = NULL;

  CHECK_EQ(SQLITE_OK,
           sqlite3_open_v2(dbfile.c_str(), &db_,
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL));

  CHECK_EQ(SQLITE_OK, sqlite3_exec(db_,
                                   "CREATE TABLE leaves(hash BLOB UNIQUE, "
                                   "entry BLOB, sequence INTEGER UNIQUE)",
                                   NULL, NULL, NULL));

  CHECK_EQ(SQLITE_OK, sqlite3_exec(db_,
                                   "CREATE TABLE trees(sth BLOB UNIQUE, "
                                   "timestamp INTEGER UNIQUE)",
                                   NULL, NULL, NULL));
  LOG(INFO) << "New SQLite database created in " << dbfile;
}


template <class Logged>
SQLiteDB<Logged>::~SQLiteDB() {
  CHECK_EQ(SQLITE_OK, sqlite3_close(db_));
}


template <class Logged>
typename Database<Logged>::WriteResult SQLiteDB<Logged>::CreateSequencedEntry_(
    const Logged& logged) {
  sqlite::Statement statement(db_,
                              "INSERT INTO leaves(hash, entry, sequence) "
                              "VALUES(?, ?, ?)");
  std::string hash = logged.Hash();
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
    hash = logged.Hash();
    s3.BindBlob(0, hash);
    CHECK_EQ(SQLITE_ROW, s3.Step());
    return this->ENTRY_ALREADY_LOGGED;
  }
  CHECK_EQ(SQLITE_DONE, ret);

  return this->OK;
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::LookupByHash(
    const std::string& hash, Logged* result) const {
  CHECK_NOTNULL(result);

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
  }
  else {
    result->set_sequence_number(statement.GetUInt64(1));
  }

  return this->LOOKUP_OK;
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::LookupByIndex(
    uint64_t sequence_number, Logged* result) const {
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

  callbacks_.Call(sth);

  return this->OK;
}


template <class Logged>
typename Database<Logged>::LookupResult SQLiteDB<Logged>::LatestTreeHead(
    ct::SignedTreeHead* result) const {
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


template <class Logged>
int SQLiteDB<Logged>::TreeSize() const {
  sqlite::Statement statement(
      db_, "SELECT sequence FROM leaves ORDER BY sequence DESC LIMIT 1");

  const int ret(statement.Step());
  if (ret == SQLITE_DONE) {
    return 0;
  }
  CHECK_EQ(SQLITE_ROW, ret);

  return statement.GetUInt64(0) + 1;
}


template <class Logged>
void SQLiteDB<Logged>::AddNotifySTHCallback(
    const typename Database<Logged>::NotifySTHCallback* callback) {
  callbacks_.Add(callback);

  ct::SignedTreeHead sth;
  if (LatestTreeHead(&sth) == this->LOOKUP_OK) {
    (*callback)(sth);
  }
}


template <class Logged>
void SQLiteDB<Logged>::RemoveNotifySTHCallback(
    const typename Database<Logged>::NotifySTHCallback* callback) {
  callbacks_.Remove(callback);
}


template <class Logged>
void SQLiteDB<Logged>::ForceNotifySTH() {
  ct::SignedTreeHead sth;

  const typename Database<Logged>::LookupResult db_result =
      this->LatestTreeHead(&sth);
  if (db_result == Database<Logged>::NOT_FOUND) {
    return;
  }

  CHECK(db_result == Database<Logged>::LOOKUP_OK);

  callbacks_.Call(sth);
}

#endif  // CERT_TRANS_LOG_SQLITE_DB_INL_H_
