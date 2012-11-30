/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef SQLITE_DB_H
#define SQLITE_DB_H
#include <string>

#include "log/database.h"

class sqlite3;

class SQLiteDB : public Database {
 public:
  explicit SQLiteDB(const std::string &dbfile);

  ~SQLiteDB();

  // Temporary, for benchmarking. If we want to do this for real, then
  // we need to implement rollbacks for errors that occur in the middle
  // of a transaction.
  virtual bool Transactional() const { return true; }

  void BeginTransaction();

  void EndTransaction();

  virtual WriteResult
  CreatePendingEntry_(const Loggable &loggable);

  virtual WriteResult
  AssignSequenceNumber(const std::string &pending_hash,
                       uint64_t sequence_number);

  virtual LookupResult
  LookupByHash(const std::string &hash, Loggable *result) const;

  virtual LookupResult
  LookupByIndex(uint64_t sequence_number, Loggable *result) const;

  virtual std::set<std::string> PendingHashes() const;

  virtual WriteResult WriteTreeHead_(const ct::SignedTreeHead &sth);

  virtual LookupResult LatestTreeHead(ct::SignedTreeHead *result) const;

 private:
  sqlite3 *db_;
};
#endif
