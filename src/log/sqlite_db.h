/* -*- mode: c++; indent-tabs-mode: nil -*- */

#include <string>

#include "database.h"

class sqlite3;

class SQLiteDB : public Database {
 public:
  SQLiteDB(const std::string &dbfile);

  virtual WriteResult
  CreatePendingCertificateEntry_(const ct::LoggedCertificate &logged_cert);

  virtual WriteResult
  AssignCertificateSequenceNumber(const bstring &pending_hash,
				  uint64_t sequence_number);

  virtual LookupResult
  LookupCertificateByHash(const bstring &certificate_sha256_hash,
                          ct::LoggedCertificate *result) const;

  virtual LookupResult
  LookupCertificateByIndex(uint64_t sequence_number,
                           ct::LoggedCertificate *result) const;

  virtual std::set<bstring> PendingHashes() const;

  virtual WriteResult WriteTreeHead_(const ct::SignedTreeHead &sth);

  virtual LookupResult LatestTreeHead(ct::SignedTreeHead *result) const;

private:
  sqlite3 *db_;
};
