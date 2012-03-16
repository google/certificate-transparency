#ifndef TREELOGGER_H
#define TREELOGGER_H
#include <string>
#include <vector>

#include <stddef.h>

#include <openssl/evp.h>

#include "LogDB.h"
#include "LogRecord.h"
#include "MerkleTree.h"

class TreeLogger {
 public:
  // TODO: make the hash function pluggable.
  TreeLogger(LogDB *db, EVP_PKEY *pkey);
  ~TreeLogger();

  // Add an entry to the current, pending segment if it doesn't already exist.
  // If key is not NULL, writes a key (= leaf hash) that can be used to look up
  // the data and its associated signatures and audit proofs later on.
  LogDB::Status QueueEntry(const std::string &data, std::string *key);

  // Get the data record corresponding to an index in a segment.
  LogDB::Status EntryInfo(size_t segment, size_t index, std::string *result);

  // Get the data record corresponding to a leaf hash.
  LogDB::Status EntryInfo(const std::string &key, LogDB::Lookup type,
                          std::string *result);

  // If the key matches a logged entry in the database, populate the fields
  // of the AuditProof (overwriting old values). If the key does not match
  // a logged entry, return the corresponding status (PENDING or NOT_FOUND).
  LogDB::Status EntryAuditProof(const std::string &key, AuditProof *proof);

  // Get the status of a segment by its index.
  // Write the segment info if the result is not NULL.
  LogDB::Status SegmentInfo(size_t index, std::string *result);

  size_t SegmentCount() const {
    return db_->SegmentCount();
  }

  size_t PendingLogSize() const { return db_->PendingLogSize(); }
  //size_t LoggedLogSize() const { return db_->LoggedLogSize(); }

  // Finalize the current segment, write it to the DB and start a new one.
  void LogSegment();

 private:
  LogDB *db_;
  EVP_PKEY *pkey_;

  // Keep all trees in memory for now.
  std::vector<MerkleTree*> logsegments_;
  MerkleTree segment_infos_;

  // Called by constructor.
  void ReadDB();
  std::string Sign(const std::string &data);
};
#endif
