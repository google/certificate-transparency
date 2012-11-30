/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef DATABASE_H
#define DATABASE_H

#include <glog/logging.h>
#include <set>

#include "proto/ct.pb.h"

class Loggable {
 public:
  Loggable() : sequence_number_set_(false), sequence_number_(0) {}
  bool has_hash() const {
    return !hash_.empty();
  }
  void set_hash(const std::string &hash) {
    CHECK(!hash.empty());
    hash_ = hash;
  }
  const std::string &hash() const {
    return hash_;
  }
  bool has_sequence_number() const {
    return sequence_number_set_;
  }
  void clear_sequence_number() {
    sequence_number_set_ = false;
    sequence_number_ = 0;
  }
  void set_sequence_number(uint64_t number) {
    sequence_number_ = number;
    sequence_number_set_ = true;
  }
  uint64_t sequence_number() const {
    return sequence_number_;
  }
  void CopyFrom(const Loggable &other) {
    set_hash(other.hash());
    if (other.has_sequence_number())
        set_sequence_number(other.sequence_number());
    else
        clear_sequence_number();
  }

  // This does _not_ need to include the hash and the sequence number.
  virtual bool SerializeToString(std::string *out) const = 0;

  // This does _not_ restore hash and sequence number
  virtual bool ParseFromString(const std::string &in) = 0;

 private:
  std::string hash_;
  bool sequence_number_set_;
  uint64_t sequence_number_;
};

// NOTE: This is a database interface for the log server.
// Monitors/auditors shouldn't assume that log entries are keyed
// uniquely by certificate hash -- it is an artefact of this
// implementation, not a requirement of the I-D.
class Database {
 public:
  enum WriteResult {
    OK,
    // Create failed, hash is primary key and must exist.
    MISSING_HASH,
    // Create failed, an entry with this hash already exists.
    DUPLICATE_HASH,
    // Update failed, entry already has a sequence number.
    ENTRY_ALREADY_LOGGED,
    // Update failed, entry does not exist.
    ENTRY_NOT_FOUND,
    // Another entry has this sequence number already.
    // We only report this if the entry is pending (i.e., ENTRY_NOT_FOUND
    // and ENTRY_ALREADY_LOGGED did not happen).
    SEQUENCE_NUMBER_ALREADY_IN_USE,
    // Timestamp is primary key, it must exist and be unique,
    DUPLICATE_TREE_HEAD_TIMESTAMP,
    MISSING_TREE_HEAD_TIMESTAMP,
  };

  enum LookupResult {
    LOOKUP_OK,
    NOT_FOUND,
  };

  virtual ~Database() {}

  virtual bool Transactional() const { return false; }

  virtual void BeginTransaction() {
    DLOG(FATAL) << "Transactions not supported";
  }

  virtual void EndTransaction() {
    DLOG(FATAL) << "Transactions not supported";
  }

  // Attempt to create a new entry. Fail if no certificate hash is given,
  // or an entry with this hash already exists.
  // The entry remains PENDING until a sequence number has been assigned,
  // after which its status changes to LOGGED.
  WriteResult
  CreatePendingEntry(const Loggable &loggable) {
    CHECK(!loggable.has_sequence_number());
    if (!loggable.has_hash())
      return MISSING_HASH;
    return CreatePendingEntry_(loggable);
  }
  // loggable will not have a sequence number when this is called.
  virtual WriteResult
  CreatePendingEntry_(const Loggable &loggable) = 0;

  // Attempt to add a sequence number to the LoggedCertificate, thereby
  // removing it from the list of pending entries.
  // Fail if the entry does not exist, already has a sequence number,
  // or an entry with this sequence number already exists (i.e.,
  // |sequence_number| is a secondary key.
  virtual WriteResult
  AssignSequenceNumber(const std::string &pending_hash,
                       uint64_t sequence_number) = 0;

  // Look up certificate by hash. If the entry exists, and result is not NULL,
  // write the result. If the entry is not logged return PENDING.
  virtual LookupResult
  LookupByHash(const std::string &hash, Loggable *result) const = 0;

  // Look up certificate by sequence number.
  virtual LookupResult
  LookupByIndex(uint64_t sequence_number, Loggable *result) const = 0;

  // List the hashes of all pending entries, i.e. all entries without a
  // sequence number.
  virtual std::set<std::string> PendingHashes() const = 0;

  // Attempt to write a tree head. Fails only if a tree head with this timestamp
  // already exists (i.e., |timestamp| is primary key). Does not check that
  // the timestamp is newer than previous entries.
  WriteResult WriteTreeHead(const ct::SignedTreeHead &sth) {
    if (!sth.has_timestamp())
      return MISSING_TREE_HEAD_TIMESTAMP;
    return WriteTreeHead_(sth);
  }
  virtual WriteResult WriteTreeHead_(const ct::SignedTreeHead &sth) = 0;

  // Return the tree head with the freshest timestamp.
  virtual LookupResult LatestTreeHead(ct::SignedTreeHead *result) const = 0;
};

#endif  // ndef DATABASE_H
