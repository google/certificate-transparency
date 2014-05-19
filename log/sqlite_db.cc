/* -*- indent-tabs-mode: nil -*- */

#include <glog/logging.h>
#include <sqlite3.h>

#include "log/sqlite_db.h"
#include "util/util.h"
#include "log/sqlite_statement.h"

using std::string;
using sqlite::Statement;

template <class Logged> SQLiteDB<Logged>::SQLiteDB(const string &dbfile)
    : db_(NULL) {
  int ret = sqlite3_open_v2(dbfile.c_str(), &db_, SQLITE_OPEN_READWRITE, NULL);
  if (ret == SQLITE_OK)
    return;
  CHECK_EQ(SQLITE_CANTOPEN, ret);

  // We have to close and reopen to avoid memory leaks.
  CHECK_EQ(SQLITE_OK, sqlite3_close(db_));
  db_ = NULL;

  CHECK_EQ(SQLITE_OK,
           sqlite3_open_v2(dbfile.c_str(), &db_,
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL));

  CHECK_EQ(SQLITE_OK, sqlite3_exec(db_, "CREATE TABLE leaves(hash BLOB UNIQUE, "
                                   "entry BLOB, sequence INTEGER UNIQUE)",
                                   NULL, NULL, NULL));

  CHECK_EQ(SQLITE_OK, sqlite3_exec(db_, "CREATE TABLE trees(sth BLOB UNIQUE, "
                                   "timestamp INTEGER UNIQUE)",
                                   NULL, NULL, NULL));
  LOG(INFO) << "New SQLite database created in " << dbfile;
}

template <class Logged> SQLiteDB<Logged>::~SQLiteDB() {
  CHECK_EQ(SQLITE_OK, sqlite3_close(db_));
}

template <class Logged> void SQLiteDB<Logged>::BeginTransaction() {
  CHECK_EQ(SQLITE_OK, sqlite3_exec(db_, "BEGIN;", NULL, NULL, NULL));
}

template <class Logged> void SQLiteDB<Logged>::EndTransaction() {
  CHECK_EQ(SQLITE_OK, sqlite3_exec(db_, "COMMIT;", NULL, NULL, NULL));
}

template <class Logged> typename Database<Logged>::WriteResult
SQLiteDB<Logged>::CreatePendingEntry_(const Logged &logged) {
  Statement statement(db_, "INSERT INTO leaves(hash, entry) "
                      "VALUES(?, ?)");
  string hash = logged.Hash();
  statement.BindBlob(0, hash);

  string data;
  CHECK(logged.SerializeForDatabase(&data));
  statement.BindBlob(1, data);

  int ret = statement.Step();
  if (ret == SQLITE_CONSTRAINT) {
    Statement s2(db_, "SELECT hash FROM leaves WHERE hash = ?");
    hash = logged.Hash();
    s2.BindBlob(0, hash);
    CHECK_EQ(SQLITE_ROW, s2.Step());
    return this->DUPLICATE_CERTIFICATE_HASH;
  }
  CHECK_EQ(SQLITE_DONE, ret);

  return this->OK;
}

template <class Logged> typename Database<Logged>::WriteResult
SQLiteDB<Logged>::AssignSequenceNumber(const string &hash,
                                       uint64_t sequence_number) {
  Statement statement(db_, "UPDATE leaves SET sequence = ? WHERE hash = ? "
                      "AND sequence IS NULL");
  statement.BindUInt64(0, sequence_number);
  statement.BindBlob(1, hash);

  int ret = statement.Step();
  if (ret == SQLITE_CONSTRAINT) {
    Statement s2(db_, "SELECT sequence FROM leaves WHERE sequence = ?");
    s2.BindUInt64(0, sequence_number);
    CHECK_EQ(SQLITE_ROW, s2.Step());
    return this->SEQUENCE_NUMBER_ALREADY_IN_USE;
  }
  CHECK_EQ(SQLITE_DONE, ret);

  int changes = sqlite3_changes(db_);
  if (changes == 0) {
    Statement s2(db_, "SELECT hash FROM leaves WHERE hash = ?");
    s2.BindBlob(0, hash);
    int ret = s2.Step();
    if (ret == SQLITE_ROW)
      return this->ENTRY_ALREADY_LOGGED;
    return this->ENTRY_NOT_FOUND;
  }
  CHECK_EQ(1, changes);

  return this->OK;
}

template <class Logged> typename Database<Logged>::LookupResult
SQLiteDB<Logged>::LookupByHash(const string &hash) const {
  Statement statement(db_, "SELECT hash FROM leaves WHERE hash = ?");
  statement.BindBlob(0, hash);

  int ret = statement.Step();
  if (ret == SQLITE_DONE)
    return this->NOT_FOUND;
  CHECK_EQ(SQLITE_ROW, ret);

  return this->LOOKUP_OK;
}
    
template <class Logged> typename Database<Logged>::LookupResult
SQLiteDB<Logged>::LookupByHash(const string &hash, Logged *result) const {
  CHECK_NOTNULL(result);

  Statement statement(db_, "SELECT entry, sequence FROM leaves "
                      "WHERE hash = ?");

  statement.BindBlob(0, hash);

  int ret = statement.Step();
  if (ret == SQLITE_DONE)
    return this->NOT_FOUND;
  CHECK_EQ(SQLITE_ROW, ret);

  string data;
  statement.GetBlob(0, &data);
  CHECK(result->ParseFromDatabase(data));

  if (statement.GetType(1) == SQLITE_NULL)
    result->clear_sequence_number();
  else
    result->set_sequence_number(statement.GetUInt64(1));

  return this->LOOKUP_OK;
}

template <class Logged> typename Database<Logged>::LookupResult
SQLiteDB<Logged>::LookupByIndex(uint64_t sequence_number,
                                Logged *result) const {
  Statement statement(db_, "SELECT entry, hash FROM leaves "
                      "WHERE sequence = ?");
  statement.BindUInt64(0, sequence_number);
  int ret = statement.Step();
  if (ret == SQLITE_DONE)
    return this->NOT_FOUND;

  string data;
  statement.GetBlob(0, &data);
  CHECK(result->ParseFromDatabase(data));

  string hash;
  statement.GetBlob(1, &hash);

  CHECK_EQ(result->Hash(), hash);

  result->set_sequence_number(sequence_number);

  return this->LOOKUP_OK;
}

template <class Logged> std::set<string>
SQLiteDB<Logged>::PendingHashes() const {
  std::set<string> hashes;
  Statement statement(db_, "SELECT hash FROM leaves WHERE sequence IS NULL");

  int ret;
  while ((ret = statement.Step()) == SQLITE_ROW) {
    string hash;
    statement.GetBlob(0, &hash);
    hashes.insert(hash);
  }
  CHECK_EQ(SQLITE_DONE, ret);

  return hashes;
}

template <class Logged> typename Database<Logged>::WriteResult
SQLiteDB<Logged>::WriteTreeHead_(const ct::SignedTreeHead &sth) {
  Statement statement(db_, "INSERT INTO trees(timestamp, sth) VALUES(?, ?)");
  statement.BindUInt64(0, sth.timestamp());

  string sth_data;
  CHECK(sth.SerializeToString(&sth_data));
  statement.BindBlob(1, sth_data);

  int r2 = statement.Step();
  if (r2 == SQLITE_CONSTRAINT) {
    Statement s2(db_, "SELECT timestamp FROM trees WHERE timestamp = ?");
    s2.BindUInt64(0, sth.timestamp());
    CHECK_EQ(SQLITE_ROW, s2.Step());
    return this->DUPLICATE_TREE_HEAD_TIMESTAMP;
  }
  CHECK_EQ(SQLITE_DONE, r2);

  return this->OK;
}

template <class Logged> typename Database<Logged>::LookupResult
SQLiteDB<Logged>::LatestTreeHead(ct::SignedTreeHead *result)
    const {
  Statement statement(db_, "SELECT sth FROM trees WHERE timestamp IN "
                      "(SELECT MAX(timestamp) FROM trees)");

  int ret = statement.Step();
  if (ret == SQLITE_DONE)
    return this->NOT_FOUND;
  CHECK_EQ(SQLITE_ROW, ret);

  string sth;
  statement.GetBlob(0, &sth);
  result->ParseFromString(sth);

  return this->LOOKUP_OK;
}
