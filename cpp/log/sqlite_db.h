/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef SQLITE_DB_H
#define SQLITE_DB_H

#include <mutex>
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

  WriteResult CreateSequencedEntry_(const Logged& logged) override;

  LookupResult LookupByHash(const std::string& hash,
                            Logged* result) const override;

  LookupResult LookupByIndex(int64_t sequence_number,
                             Logged* result) const override;

  WriteResult WriteTreeHead_(const ct::SignedTreeHead& sth) override;

  LookupResult LatestTreeHead(ct::SignedTreeHead* result) const override;

  int64_t TreeSize() const override;

  void AddNotifySTHCallback(
      const typename Database<Logged>::NotifySTHCallback* callback) override;

  void RemoveNotifySTHCallback(
      const typename Database<Logged>::NotifySTHCallback* callback) override;

  // Force an STH notification. This is needed only for ct-dns-server,
  // which shares a SQLite database with ct-server, but needs to
  // refresh itself occasionally.
  void ForceNotifySTH();

 private:
  LookupResult LatestTreeHeadNoLock(ct::SignedTreeHead* result) const;
  void UpdateTreeSize();

  mutable std::mutex lock_;
  sqlite3* const db_;
  int64_t tree_size_;
  cert_trans::DatabaseNotifierHelper callbacks_;

  DISALLOW_COPY_AND_ASSIGN(SQLiteDB);
};

#endif
