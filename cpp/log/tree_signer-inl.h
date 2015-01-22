/* -*- indent-tabs-mode: nil -*- */
#ifndef CERT_TRANS_LOG_TREE_SIGNER_INL_H_
#define CERT_TRANS_LOG_TREE_SIGNER_INL_H_

#include "log/tree_signer.h"

#include <algorithm>
#include <chrono>
#include <glog/logging.h>
#include <set>
#include <stdint.h>

#include "log/database.h"
#include "log/consistent_store.h"
#include "log/log_signer.h"
#include "merkletree/compact_merkle_tree.h"
#include "proto/serializer.h"
#include "util/status.h"
#include "util/util.h"


namespace cert_trans {

// Comparator for ordering pending hashes.
// We want provisionally sequenced entries before unsequenced ones, sorted by
// sequence number.  Remaining entries should be sorted by their timestamps,
// then hashes.
template <class Logged>
struct PendingEntriesOrder
    : std::binary_function<const cert_trans::EntryHandle<Logged>&,
                           const cert_trans::EntryHandle<Logged>&, bool> {
  bool operator()(const cert_trans::EntryHandle<Logged>& x,
                  const cert_trans::EntryHandle<Logged>& y) const {
    // Test provisional sequence number first
    const bool x_has_seq(x.Entry().has_provisional_sequence_number());
    const bool y_has_seq(y.Entry().has_provisional_sequence_number());
    if (x_has_seq && !y_has_seq) {
      return true;
    } else if (!x_has_seq && y_has_seq) {
      return false;
    } else if (x_has_seq && y_has_seq) {
      const int64_t x_seq(x.Entry().provisional_sequence_number());
      const int64_t y_seq(y.Entry().provisional_sequence_number());
      CHECK_GE(x_seq, 0);
      CHECK_GE(y_seq, 0);
      if (x_seq < y_seq) {
        return true;
      } else if (x_seq > y_seq) {
        return false;
      }
    }

    // If we're still here, then either x and y don't have sequence numbers, or
    // they're equal, so fallback to timestamps (which both x and y MUST
    // have.):
    CHECK(x.Entry().contents().sct().has_timestamp());
    CHECK(y.Entry().contents().sct().has_timestamp());
    const uint64_t x_time(x.Entry().contents().sct().timestamp());
    const uint64_t y_time(y.Entry().contents().sct().timestamp());
    if (x_time < y_time) {
      return true;
    } else if (x_time > y_time) {
      return false;
    }

    // Fallback to Hash as a final tie-breaker:
    return x.Entry().Hash() < y.Entry().Hash();
  }
};


template <class Logged>
TreeSigner<Logged>::TreeSigner(
    const std::chrono::duration<double>& guard_window, Database<Logged>* db,
    cert_trans::ConsistentStore<Logged>* consistent_store, LogSigner* signer)
    : guard_window_(guard_window),
      db_(db),
      consistent_store_(consistent_store),
      signer_(signer),
      cert_tree_(new Sha256Hasher()),
      latest_tree_head_() {
  BuildTree();
}


template <class Logged>
uint64_t TreeSigner<Logged>::LastUpdateTime() const {
  // Returns 0 if we have no update yet (i.e., the field is not set).
  return latest_tree_head_.timestamp();
}


template <class Logged>
util::Status TreeSigner<Logged>::HandlePreviouslySequencedEntries(
    std::vector<cert_trans::EntryHandle<Logged>>* pending_entries) const {
  CHECK(std::is_sorted(pending_entries->begin(), pending_entries->end(),
                       PendingEntriesOrder<Logged>()));
  // Check and handle any previously sequenced entries
  util::Status status;
  auto it(pending_entries->begin());
  while (it != pending_entries->end()) {
    if (!it->Entry().has_provisional_sequence_number()) {
      // There can't be any more entries with provisional sequence numbers now
      // (because of the sort order) so we can early out.
      break;
    }
    cert_trans::EntryHandle<Logged> presequenced;
    status = consistent_store_->GetSequencedEntry(
        it->Entry().provisional_sequence_number(), &presequenced);
    if (status.ok()) {
      CHECK(it->Entry().entry() == presequenced.Entry().entry() &&
            it->Entry().sct() == presequenced.Entry().sct())
          << "Pending entry with provisional_sequence_number:\n"
          << it->Entry().DebugString() << "\n"
          << "does not match sequenced entry for that sequence "
          << "number:\n" << presequenced.Entry().DebugString()
          << "\nclearing provisional_sequence_number to "
          << "resequence pending entry";
      // This entry is already sequenced just fine, no need to return it.
      VLOG(0) << "Entry already sequenced: "
              << util::ToBase64(it->Entry().Hash()) << " ("
              << presequenced.Entry().sequence_number()
              << "), removing from list";
      it = pending_entries->erase(it);
      continue;
    }
    if (status.CanonicalCode() != util::error::NOT_FOUND) {
      return status;
    }
    // provisional sequence number set, but entry not actually sequenced:
    // This is likely the result of a sequencer crash, we'll leave the
    // provisional sequence number set as a hint to the sequencer.
    ++it;
  }
  return status;
}


template <class Logged>
util::Status TreeSigner<Logged>::SequenceNewEntries() {
  const std::chrono::system_clock::time_point now(
      std::chrono::system_clock::now());
  util::StatusOr<int64_t> status_or_sequence_number(
      consistent_store_->NextAvailableSequenceNumber());
  if (!status_or_sequence_number.ok()) {
    return status_or_sequence_number.status();
  }
  int64_t next_sequence_number(status_or_sequence_number.ValueOrDie());
  CHECK_GE(next_sequence_number, 0);
  VLOG(1) << "Next available sequence number: " << next_sequence_number;
  std::vector<cert_trans::EntryHandle<Logged>> pending_entries;
  util::Status status(consistent_store_->GetPendingEntries(&pending_entries));
  if (!status.ok()) {
    return status;
  }
  std::sort(pending_entries.begin(), pending_entries.end(),
            PendingEntriesOrder<Logged>());

  VLOG(1) << "Sequencing " << pending_entries.size() << " entr"
          << (pending_entries.size() == 1 ? "y" : "ies");

  status = HandlePreviouslySequencedEntries(&pending_entries);
  CHECK(status.ok()) << status;

  int num_sequenced(0);
  for (auto& pending_entry : pending_entries) {
    const std::chrono::system_clock::time_point cert_time(
        std::chrono::milliseconds(pending_entry.Entry().timestamp()));
    if (now - cert_time < guard_window_) {
      VLOG(1) << "Entry too recent: "
              << util::ToBase64(pending_entry.Entry().Hash());
      continue;
    }

    if (pending_entry.Entry().has_provisional_sequence_number()) {
      // This is a recovery from a crashed sequencer run.
      // Since the sequencing order is deterministic the assigned provisional
      // sequence number should match our expectation:
      CHECK_EQ(next_sequence_number,
               pending_entry.Entry().provisional_sequence_number());
    }
    VLOG(0) << util::ToBase64(pending_entry.Entry().Hash()) << " = "
            << next_sequence_number;
    status = consistent_store_->AssignSequenceNumber(next_sequence_number,
                                                     &pending_entry);
    if (!status.ok()) {
      return status;
    }
    ++num_sequenced;
    ++next_sequence_number;
  }

  VLOG(1) << "Sequenced " << num_sequenced << " entries.";

  return util::Status::OK;
}


// DB_ERROR: the database is inconsistent with our inner self.
// However, if the database itself is giving inconsistent answers, or failing
// reads/writes, then we die.
template <class Logged>
typename TreeSigner<Logged>::UpdateResult TreeSigner<Logged>::UpdateTree() {
  // Check that the latest sth is ours.
  ct::SignedTreeHead sth;
  typename Database<Logged>::LookupResult db_result =
      db_->LatestTreeHead(&sth);

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

  util::Status status(SequenceNewEntries());
  CHECK(status.ok()) << status;

  EntryHandle<Logged> logged;
  int64_t next_seq(sth.tree_size());
  CHECK_GE(next_seq, 0);
  VLOG(1) << "Building tree";
  while (true) {
    status = consistent_store_->GetSequencedEntry(next_seq, &logged);
    if (status.CanonicalCode() == util::error::NOT_FOUND) {
      // no more certs to integrate (or a gap in the sequence numbers, but
      // that'd be bad so we should bail anyway.)
      break;
    }
    CHECK(status.ok()) << status;
    // Paranoid much?
    CHECK(logged.Entry().has_sequence_number());
    CHECK_EQ(next_seq, logged.Entry().sequence_number());

    if (!Append(logged.Entry())) {
      LOG(ERROR) << "Assigning sequence number failed";
      return DB_ERROR;
    }

    if (logged.Entry().timestamp() > min_timestamp) {
      min_timestamp = logged.Entry().timestamp();
    }
    ++next_seq;
  }

  // Our tree is consistent with the database, i.e., each leaf in the tree has
  // a matching sequence number in the database (at least assuming overwriting
  // the sequence number is not allowed).
  ct::SignedTreeHead new_sth;
  TimestampAndSign(min_timestamp, &new_sth);

  // TODO(ekasper): if we allow multiple processes to modify the database,
  // then we should lock the database file here and check again that we still
  // own the latest STH.
  CHECK_EQ(Database<Logged>::OK, db_->WriteTreeHead(new_sth));
  latest_tree_head_.CopyFrom(new_sth);
  return OK;
}


template <class Logged>
void TreeSigner<Logged>::BuildTree() {
  DCHECK_EQ(0U, cert_tree_.LeafCount())
      << "Attempting to build a tree when one already exists";
  // Read the latest sth.
  ct::SignedTreeHead sth;
  typename Database<Logged>::LookupResult db_result =
      db_->LatestTreeHead(&sth);

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

  // Read the remaining sequenced entries. Note that it is possible to have
  // more
  // entries with sequence numbers than what the latest sth says. This happens
  // when we assign some sequence numbers but die before we manage to sign the
  // sth. It's not an inconsistency and will be corrected with UpdateTree().
  for (size_t i = sth.tree_size();; ++i) {
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


template <class Logged>
bool TreeSigner<Logged>::Append(const Logged& logged) {
  // Serialize for inclusion in the tree.
  std::string serialized_leaf;
  CHECK(logged.SerializeForLeaf(&serialized_leaf));

  CHECK_EQ(logged.sequence_number(), cert_tree_.LeafCount());
  // Commit the sequence number of this certificate locally
  typename Database<Logged>::WriteResult db_result =
      db_->CreateSequencedEntry(logged);

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


template <class Logged>
void TreeSigner<Logged>::AppendToTree(const Logged& logged) {
  // Serialize for inclusion in the tree.
  std::string serialized_leaf;
  CHECK(logged.SerializeForLeaf(&serialized_leaf));

  // Update in-memory tree.
  cert_tree_.AddLeaf(serialized_leaf);
}


template <class Logged>
void TreeSigner<Logged>::TimestampAndSign(uint64_t min_timestamp,
                                          ct::SignedTreeHead* sth) {
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


}  // namespace cert_trans


#endif  // CERT_TRANS_LOG_TREE_SIGNER_INL_H_
