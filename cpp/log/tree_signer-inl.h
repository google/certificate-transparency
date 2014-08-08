/* -*- indent-tabs-mode: nil -*- */
#ifndef CERT_TRANS_LOG_TREE_SIGNER_INL_H_
#define CERT_TRANS_LOG_TREE_SIGNER_INL_H_

#include "log/tree_signer.h"

#include <glog/logging.h>
#include <set>
#include <stdint.h>

#include "log/database.h"
#include "log/log_signer.h"
#include "merkletree/compact_merkle_tree.h"
#include "proto/serializer.h"
#include "util/util.h"

using ct::SignedTreeHead;
using std::string;

template <class Logged>
TreeSigner<Logged>::TreeSigner(Database<Logged> *db, LogSigner *signer)
    : db_(db),
      signer_(signer),
      cert_tree_(new Sha256Hasher()),
      latest_tree_head_() {
  BuildTree();
}

template <class Logged> uint64_t TreeSigner<Logged>::LastUpdateTime() const {
  // Returns 0 if we have no update yet (i.e., the field is not set).
  return latest_tree_head_.timestamp();
}

// DB_ERROR: the database is inconsistent with our inner self.
// However, if the database itself is giving inconsistent answers, or failing
// reads/writes, then we die.
template <class Logged> typename TreeSigner<Logged>::UpdateResult
TreeSigner<Logged>::UpdateTree() {
  // Check that the latest sth is ours.
  SignedTreeHead sth;
  typename Database<Logged>::LookupResult db_result = db_->LatestTreeHead(&sth);

  if (db_result == Database<Logged>::NOT_FOUND) {
    if (LastUpdateTime() != 0) {
      LOG(ERROR) << "Latest STH missing from database, signer has:\n"
          << latest_tree_head_.DebugString();
      return DB_ERROR;
    }
  } else {
    CHECK_EQ(db_result, Database<Logged>::LOOKUP_OK)
        << "Latest STH lookup failed";
    if (sth.timestamp() != latest_tree_head_.timestamp() ||
            sth.tree_size() != latest_tree_head_.tree_size() ||
        sth.sha256_root_hash() != latest_tree_head_.sha256_root_hash()) {
      LOG(ERROR) << "Database has an STH that does not match ours. "
                 << "Our STH:\n" << latest_tree_head_.DebugString()
                 << "Database STH:\n" << sth.DebugString();
      return DB_ERROR;
    }
  }

  // Timestamps have to be unique.
  uint64_t min_timestamp = LastUpdateTime() + 1;

  std::set<string> pending_hashes = db_->PendingHashes();
  std::set<string>::const_iterator it;
  for (it = pending_hashes.begin(); it != pending_hashes.end(); ++it) {
    Logged logged;
    CHECK_EQ(Database<Logged>::LOOKUP_OK, db_->LookupByHash(*it, &logged))
        << "Failed to look up pending entry with hash " << util::HexString(*it);

    CHECK(!logged.has_sequence_number())
        << "Pending entry already has a sequence number; entry is "
        << logged.DebugString();

    CHECK_EQ(logged.Hash(), *it);
    if (!Append(logged)) {
      LOG(ERROR) << "Assigning sequence number failed";
      return DB_ERROR;
    }

    if (logged.timestamp() > min_timestamp)
      min_timestamp = logged.timestamp();
  }

  // Our tree is consistent with the database, i.e., each leaf in the tree has
  // a matching sequence number in the database (at least assuming overwriting
  // the sequence number is not allowed).
  SignedTreeHead new_sth;
  TimestampAndSign(min_timestamp, &new_sth);

  // TODO(ekasper): if we allow multiple processes to modify the database,
  // then we should lock the database file here and check again that we still
  // own the latest STH.
  CHECK_EQ(Database<Logged>::OK, db_->WriteTreeHead(new_sth));
  latest_tree_head_.CopyFrom(new_sth);
  return OK;
}

template <class Logged> void TreeSigner<Logged>::BuildTree() {
  DCHECK_EQ(0U, cert_tree_.LeafCount())
      << "Attempting to build a tree when one already exists";
  // Read the latest sth.
  SignedTreeHead sth;
  typename Database<Logged>::LookupResult db_result = db_->LatestTreeHead(&sth);

  if (db_result == Database<Logged>::NOT_FOUND)
    return;

  CHECK(db_result == Database<Logged>::LOOKUP_OK);

  // If the timestamp is from the future, then either the database is corrupt
  // or our clock is corrupt; either way we shouldn't be signing things.
  uint64_t current_time = util::TimeInMilliseconds();
  CHECK_LE(sth.timestamp(), current_time)
      << "Database has a timestamp from the future.";

  // Read all logged and signed entries.
  for (size_t i = 0; i < sth.tree_size(); ++i) {
    Logged logged;
    CHECK_EQ(Database<Logged>::LOOKUP_OK, db_->LookupByIndex(i, &logged));
    CHECK_LE(logged.timestamp(), sth.timestamp());
    CHECK_EQ(logged.sequence_number(), i);

    AppendToTree(logged);
  }

  // Check the root hash.
  CHECK_EQ(cert_tree_.CurrentRoot(), sth.sha256_root_hash());

  latest_tree_head_.CopyFrom(sth);

  // Read the remaining sequenced entries. Note that it is possible to have more
  // entries with sequence numbers than what the latest sth says. This happens
  // when we assign some sequence numbers but die before we manage to sign the
  // sth. It's not an inconsistency and will be corrected with UpdateTree().
  for (size_t i = sth.tree_size(); ; ++i) {
    Logged logged;
    typename Database<Logged>::LookupResult db_result =
        db_->LookupByIndex(i, &logged);
    if (db_result == Database<Logged>::NOT_FOUND)
      break;
    CHECK_EQ(Database<Logged>::LOOKUP_OK, db_result);
    CHECK_EQ(logged.sequence_number(), i);

    AppendToTree(logged);
  }
}

template <class Logged> bool
TreeSigner<Logged>::Append(const Logged &logged) {
  // Serialize for inclusion in the tree.
  string serialized_leaf;
  CHECK(logged.SerializeForLeaf(&serialized_leaf));

  // Commit the sequence number of this certificate.
  typename Database<Logged>::WriteResult db_result =
      db_->AssignSequenceNumber(logged.Hash(), cert_tree_.LeafCount());

  if (db_result != Database<Logged>::OK) {
    CHECK_EQ(Database<Logged>::SEQUENCE_NUMBER_ALREADY_IN_USE, db_result);
    LOG(ERROR) << "Attempt to assign duplicate sequence number "
               << cert_tree_.LeafCount();
    return false;
  }

  // Update in-memory tree.
  cert_tree_.AddLeaf(serialized_leaf);
  return true;
}

template <class Logged> void
TreeSigner<Logged>::AppendToTree(const Logged &logged) {
  // Serialize for inclusion in the tree.
  string serialized_leaf;
  CHECK(logged.SerializeForLeaf(&serialized_leaf));

  // Update in-memory tree.
  cert_tree_.AddLeaf(serialized_leaf);
}

template <class Logged> void
TreeSigner<Logged>::TimestampAndSign(uint64_t min_timestamp,
                                     SignedTreeHead *sth) {
  sth->set_version(ct::V1);
  sth->set_sha256_root_hash(cert_tree_.CurrentRoot());
  uint64_t timestamp = util::TimeInMilliseconds();
  if (timestamp < min_timestamp)
    // TODO(ekasper): shouldn't really happen if everyone's clocks are in sync;
    // log a warning if the skew is over some threshold?
    timestamp = min_timestamp;
  sth->set_timestamp(timestamp);
  sth->set_tree_size(cert_tree_.LeafCount());
  LogSigner::SignResult ret = signer_->SignTreeHead(sth);
  if (ret != LogSigner::OK)
    // Make this one a hard fail. There is really no excuse for it.
    abort();
}

#endif  // CERT_TRANS_LOG_TREE_SIGNER_INL_H_
