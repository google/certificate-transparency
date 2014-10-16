/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef SQLITE_DB_H
#define SQLITE_DB_H
#include <string>

#include "base/macros.h"
#include "log/database.h"

struct sqlite3;

template <class Logged>
class SQLiteDB : public Database<Logged> {
 public:
  explicit SQLiteDB(const std::string& dbfile);

  ~SQLiteDB();

  typedef typename Database<Logged>::WriteResult WriteResult;
  typedef typename Database<Logged>::LookupResult LookupResult;

  virtual WriteResult CreatePendingEntry_(const Logged& logged);

  virtual WriteResult AssignSequenceNumber(const std::string& pending_hash,
                                           uint64_t sequence_number);

  virtual LookupResult LookupByHash(const std::string& hash,
                                    Logged* result) const;

  virtual LookupResult LookupByIndex(uint64_t sequence_number,
                                     Logged* result) const;

  virtual std::set<std::string> PendingHashes() const;

  virtual WriteResult WriteTreeHead_(const ct::SignedTreeHead& sth);

  virtual LookupResult LatestTreeHead(ct::SignedTreeHead* result) const;

 private:
  sqlite3* db_;

  DISALLOW_COPY_AND_ASSIGN(SQLiteDB);
};

#endif
