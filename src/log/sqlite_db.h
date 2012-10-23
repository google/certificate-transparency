/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef SQLITE_DB_H
#define SQLITE_DB_H
#include <string>

#include "database.h"

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
  CreatePendingCertificateEntry_(const ct::LoggedCertificate &logged_cert);

  virtual WriteResult
  AssignCertificateSequenceNumber(const std::string &pending_hash,
                                  uint64_t sequence_number);

  virtual LookupResult
  LookupCertificateByHash(const std::string &certificate_sha256_hash,
                          ct::LoggedCertificate *result) const;

  virtual LookupResult
  LookupCertificateByIndex(uint64_t sequence_number,
                           ct::LoggedCertificate *result) const;

  virtual std::set<std::string> PendingHashes() const;

  virtual WriteResult WriteTreeHead_(const ct::SignedTreeHead &sth);

  virtual LookupResult LatestTreeHead(ct::SignedTreeHead *result) const;

 private:
  sqlite3 *db_;
};
#endif
