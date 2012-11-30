/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef FRONTEND_SIGNER_H
#define FRONTEND_SIGNER_H

#include <stdint.h>
#include <string>

#include "database.h"
#include "proto/ct.pb.h"

class Database;
class LogSigner;

namespace ct {

class LoggedCertificate : public Loggable {
 public:
  ct::SignedCertificateTimestamp *mutable_sct() {
    return logged_cert_.mutable_sct();
  }
  const ct::SignedCertificateTimestamp &sct() const {
    return logged_cert_.sct();
  }
  ct::LogEntry *mutable_entry() {
    return logged_cert_.mutable_entry();
  }
  const ct::LogEntry &entry() const {
    return logged_cert_.entry();
  }
  void set_merkle_leaf_hash(const std::string &hash) {
    logged_cert_.set_merkle_leaf_hash(hash);
  }
  const std::string &merkle_leaf_hash() const {
    return logged_cert_.merkle_leaf_hash();
  }
  bool SerializeToString(std::string *out) const {
    return logged_cert_.SerializeToString(out);
  }
  bool ParseFromString(const std::string &in) {
    return logged_cert_.ParseFromString(in);
  }
  std::string DebugString() const {
    // FIXME: show hash/seq
    return logged_cert_.DebugString();
  }
  void CopyFrom(const LoggedCertificate &cert) {
    logged_cert_ = cert.logged_cert_;
    Loggable::CopyFrom(cert);
  }
 private:
  ct::LoggedCertificatePB logged_cert_;
};

};  // namespace ct

class FrontendSigner {
 public:
  enum SubmitResult {
    NEW,
    DUPLICATE,
  };

  // Takes ownership of |signer|.
  FrontendSigner(Database *db, LogSigner *signer);

  ~FrontendSigner();

  // Log the entry if it's not already in the database,
  // and return either a new timestamp-signature pair,
  // or a previously existing one. (Currently also copies the
  // entry to the sct but you shouldn't rely on this.)
  SubmitResult QueueEntry(const ct::LogEntry &entry,
                          ct::SignedCertificateTimestamp *sct);

 private:
  Database *db_;
  LogSigner *signer_;

  void TimestampAndSign(const ct::LogEntry &entry,
                        ct::SignedCertificateTimestamp *sct) const;
};
#endif
