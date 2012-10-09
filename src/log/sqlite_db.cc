/* -*- indent-tabs-mode: nil -*- */

#include <iostream>
#include <sqlite3.h>

#include "sqlite_db.h"
#include "util.h"

using std::string;

SQLiteDB::SQLiteDB(const string &dbfile) {
  int ret = sqlite3_open_v2(dbfile.c_str(), &db_, SQLITE_OPEN_READWRITE, NULL);
  if (ret == SQLITE_OK)
    return;
  assert(ret == SQLITE_CANTOPEN);

  ret = sqlite3_open_v2(dbfile.c_str(), &db_,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
  assert(ret == SQLITE_OK);
  ret = sqlite3_exec(db_, "CREATE TABLE leaves(hash BLOB UNIQUE, sct BLOB, "
                     "sequence INTEGER UNIQUE)",
                     NULL, NULL, NULL);
  assert(ret == SQLITE_OK);
  ret = sqlite3_exec(db_, "CREATE TABLE trees(sth BLOB UNIQUE, "
                     "timestamp INTEGER UNIQUE)",
                     NULL, NULL, NULL);
  assert(ret == SQLITE_OK);
}

// Reduce the ugliness of the sqlite3 API.
class Statement {
public:
  Statement(sqlite3 *db, const char *sql) : stmt_(NULL) {
    int ret = sqlite3_prepare_v2(db, sql, -1, &stmt_, NULL);
    assert(ret == SQLITE_OK);
  }

  ~Statement() {
    int ret = sqlite3_finalize(stmt_);
    // can get SQLITE_CONSTRAINT if an insert failed due to a duplicate key.
    assert(ret == SQLITE_OK || ret == SQLITE_CONSTRAINT);
  }

  // Fields start at 0! |value| must have lifetime that covers its
  // use, which is up until the SQL statement finishes executing
  // (i.e. after the last Step()).
  void BindBlob(unsigned field, const string &value) {
    int ret = sqlite3_bind_blob(stmt_, field + 1, value.data(), value.length(),
                                NULL);
    assert(ret == SQLITE_OK);
  }

  void BindUInt64(unsigned field, sqlite3_uint64 value) {
    int ret = sqlite3_bind_int64(stmt_, field + 1, value);
    assert(ret == SQLITE_OK);
  }

  void GetBlob(unsigned column, string *value) {
    const void *data = sqlite3_column_blob(stmt_, column);
    assert(data != NULL);
    value->assign(static_cast<const char *>(data),
                  sqlite3_column_bytes(stmt_, column));
  }

  sqlite3_uint64 GetUInt64(unsigned column) {
    return sqlite3_column_int64(stmt_, column);
  }

  int GetType(unsigned column) {
    return sqlite3_column_type(stmt_, column);
  }

  int Step() {
    return sqlite3_step(stmt_);
  }

private:
  sqlite3_stmt *stmt_;
};

Database::WriteResult
SQLiteDB::CreatePendingCertificateEntry_(const ct::LoggedCertificate &cert) {
  Statement statement(db_, "INSERT INTO leaves(hash, sct) VALUES(?, ?)");

  statement.BindBlob(0, cert.certificate_sha256_hash());

  string sct_data;
  bool r2 = cert.sct().SerializeToString(&sct_data);
  assert(r2);
  statement.BindBlob(1, sct_data);

  int ret = statement.Step();
  if (ret == SQLITE_CONSTRAINT) {
    Statement s2(db_, "SELECT hash FROM leaves WHERE hash = ?");
    s2.BindBlob(0, cert.certificate_sha256_hash());
    ret = s2.Step();
    assert(ret == SQLITE_ROW);
    return DUPLICATE_CERTIFICATE_HASH;
  }
  assert(ret == SQLITE_DONE);

  return OK;
}

Database::WriteResult
SQLiteDB::AssignCertificateSequenceNumber(const string &hash,
                                          uint64_t sequence_number) {
  Statement statement(db_, "UPDATE leaves SET sequence = ? WHERE hash = ? "
                      "AND sequence IS NULL");
  statement.BindUInt64(0, sequence_number);
  statement.BindBlob(1, hash);

  int ret = statement.Step();
  if (ret == SQLITE_CONSTRAINT) {
    Statement s2(db_, "SELECT sequence FROM leaves WHERE sequence = ?");
    s2.BindUInt64(0, sequence_number);
    int ret = s2.Step();
    assert(ret == SQLITE_ROW);
    return SEQUENCE_NUMBER_ALREADY_IN_USE;
  }
  assert(ret == SQLITE_DONE);

  int changes = sqlite3_changes(db_);
  if (changes == 0) {
    Statement s2(db_, "SELECT hash FROM leaves WHERE hash = ?");
    s2.BindBlob(0, hash);
    int ret = s2.Step();
    if (ret == SQLITE_ROW)
      return ENTRY_ALREADY_LOGGED;
    return ENTRY_NOT_FOUND;
  }
  assert(changes == 1);

  return OK;
}

Database::LookupResult
SQLiteDB::LookupCertificateByHash(const string &hash,
                                  ct::LoggedCertificate *result) const {
  Statement statement(db_, "SELECT sct, sequence FROM leaves WHERE hash = ?");

  statement.BindBlob(0, hash);

  int ret = statement.Step();
  if (ret == SQLITE_DONE)
    return NOT_FOUND;
  assert(ret == SQLITE_ROW);

  string sct;
  statement.GetBlob(0, &sct);
  result->mutable_sct()->ParseFromString(sct);

  if (statement.GetType(1) == SQLITE_NULL)
    result->clear_sequence_number();
  else
    result->set_sequence_number(statement.GetUInt64(1));

  result->set_certificate_sha256_hash(hash);
      
  return LOOKUP_OK;
}

Database::LookupResult
SQLiteDB::LookupCertificateByIndex(uint64_t sequence_number,
                                   ct::LoggedCertificate *result) const {
  Statement statement(db_, "SELECT sct, hash FROM leaves WHERE sequence = ?");
  statement.BindUInt64(0, sequence_number);
  int ret = statement.Step();
  if (ret == SQLITE_DONE)
    return NOT_FOUND;

  string sct;
  statement.GetBlob(0, &sct);
  result->mutable_sct()->ParseFromString(sct);

  string hash;
  statement.GetBlob(1, &hash);
  result->set_certificate_sha256_hash(hash);

  result->set_sequence_number(sequence_number);

  return LOOKUP_OK;
}

std::set<string> SQLiteDB::PendingHashes() const {
  std::set<string> hashes;
  Statement statement(db_, "SELECT hash FROM leaves WHERE sequence IS NULL");

  int ret;
  while ((ret = statement.Step()) == SQLITE_ROW) {
    string hash;
    statement.GetBlob(0, &hash);
    hashes.insert(hash);
  }
  assert(ret == SQLITE_DONE);

  return hashes;
}

Database::WriteResult SQLiteDB::WriteTreeHead_(const ct::SignedTreeHead &sth) {
  Statement statement(db_, "INSERT INTO trees(timestamp, sth) VALUES(?, ?)");
  statement.BindUInt64(0, sth.timestamp());

  string sth_data;
  bool ret = sth.SerializeToString(&sth_data);
  assert(ret);
  statement.BindBlob(1, sth_data);

  int r2 = statement.Step();
  if (r2 == SQLITE_CONSTRAINT) {
    Statement s2(db_, "SELECT timestamp FROM trees WHERE timestamp = ?");
    s2.BindUInt64(0, sth.timestamp());
    r2 = s2.Step();
    assert(r2 == SQLITE_ROW);
    return DUPLICATE_TREE_HEAD_TIMESTAMP;
  }
  assert(r2 == SQLITE_DONE);

  return OK;
}

Database::LookupResult SQLiteDB::LatestTreeHead(ct::SignedTreeHead *result)
  const {
  Statement statement(db_, "SELECT sth FROM trees WHERE timestamp IN "
                      "(SELECT MAX(timestamp) FROM trees)");

  int ret = statement.Step();
  if (ret == SQLITE_DONE)
    return NOT_FOUND;
  assert(ret == SQLITE_ROW);
  
  string sth;
  statement.GetBlob(0, &sth);
  result->ParseFromString(sth);

  return LOOKUP_OK;
}
