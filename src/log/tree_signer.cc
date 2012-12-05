#include <glog/logging.h>
#include <set>
#include <stdint.h>

#include "log/database.h"
#include "log/log_signer.h"
#include "log/tree_signer.h"
#include "merkletree/compact_merkle_tree.h"
#include "proto/serializer.h"
#include "util/util.h"

using ct::LoggedCertificate;
using ct::SignedTreeHead;
using std::string;

TreeSigner::TreeSigner(Database *db, LogSigner *signer)
    : db_(db),
      signer_(signer),
      cert_tree_(new Sha256Hasher()),
      latest_tree_head_() {
  BuildTree();
}

TreeSigner::~TreeSigner() {
  delete signer_;
}

uint64_t TreeSigner::LastUpdateTime() const {
  // Returns 0 if we have no update yet (i.e., the field is not set).
  return latest_tree_head_.timestamp();
}

// DB_ERROR: the database is inconsistent with our inner self.
// However, if the database itself is giving inconsistent answers, or failing
// reads/writes, then we die.
TreeSigner::UpdateResult TreeSigner::UpdateTree() {
  // Check that the latest sth is ours.
  SignedTreeHead sth;
  Database::LookupResult db_result = db_->LatestTreeHead(&sth);

  if (db_result == Database::NOT_FOUND) {
    if (LastUpdateTime() != 0) {
      LOG(ERROR) << "Latest STH missing from database, signer has:\n"
          << latest_tree_head_.DebugString();
      return DB_ERROR;
    }
  } else {
    CHECK_EQ(db_result, Database::LOOKUP_OK) << "Latest STH lookup failed";
    if (sth.timestamp() != latest_tree_head_.timestamp() ||
            sth.tree_size() != latest_tree_head_.tree_size() ||
        sth.root_hash() != latest_tree_head_.root_hash()) {
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
    LoggedCertificate logged_cert;
    CHECK_EQ(Database::LOOKUP_OK,
             db_->LookupCertificateByHash(*it, &logged_cert))
        << "Failed to look up pending entry with hash " << util::HexString(*it);

    CHECK(!logged_cert.has_sequence_number())
        << "Pending entry already has a sequence number; entry is "
        << logged_cert.DebugString();

    CHECK_EQ(logged_cert.certificate_sha256_hash(), *it);
    if (!AppendCertificate(logged_cert)) {
      LOG(ERROR) << "Assigning sequence number failed";
      return DB_ERROR;
    }

    if (logged_cert.sct().timestamp() > min_timestamp)
      min_timestamp = logged_cert.sct().timestamp();
  }

  // Our tree is consistent with the database, i.e., each leaf in the tree has
  // a matching sequence number in the database (at least assuming overwriting
  // the sequence number is not allowed).
  SignedTreeHead new_sth;
  TimestampAndSign(min_timestamp, &new_sth);

  // TODO(ekasper): if we allow multiple processes to modify the database,
  // then we should lock the database file here and check again that we still
  // own the latest STH.
  CHECK_EQ(Database::OK, db_->WriteTreeHead(new_sth));
  latest_tree_head_.CopyFrom(new_sth);
  return OK;
}

void TreeSigner::BuildTree() {
  DCHECK_EQ(0U, cert_tree_.LeafCount())
      << "Attempting to build a tree when one already exists";
  // Read the latest sth.
  SignedTreeHead sth;
  Database::LookupResult db_result = db_->LatestTreeHead(&sth);

  if (db_result == Database::NOT_FOUND)
    return;

  CHECK(db_result == Database::LOOKUP_OK);

  // If the timestamp is from the future, then either the database is corrupt
  // or our clock is corrupt; either way we shouldn't be signing things.
  uint64_t current_time = util::TimeInMilliseconds();
  CHECK_LE(sth.timestamp(), current_time)
      << "Database has a timestamp from the future.";

  // Read all logged and signed entries.
  for (size_t i = 0; i < sth.tree_size(); ++i) {
    LoggedCertificate logged_cert;
    CHECK_EQ(Database::LOOKUP_OK,
             db_->LookupCertificateByIndex(i, &logged_cert));
    CHECK_LE(logged_cert.sct().timestamp(), sth.timestamp());
    CHECK_EQ(logged_cert.sequence_number(), i);

    AppendCertificateToTree(logged_cert);
  }

  // Check the root hash.
  CHECK_EQ(cert_tree_.CurrentRoot(), sth.root_hash());

  latest_tree_head_.CopyFrom(sth);

  // Read the remaining sequenced entries. Note that it is possible to have more
  // entries with sequence numbers than what the latest sth says. This happens
  // when we assign some sequence numbers but die before we manage to sign the
  // sth. It's not an inconsistency and will be corrected with UpdateTree().
  for (size_t i = sth.tree_size(); ; ++i) {
    LoggedCertificate logged_cert;
    Database::LookupResult db_result =
        db_->LookupCertificateByIndex(i, &logged_cert);
    if (db_result == Database::NOT_FOUND)
      break;
    CHECK_EQ(Database::LOOKUP_OK, db_result);
    CHECK_EQ(logged_cert.sequence_number(), i);

    AppendCertificateToTree(logged_cert);
  }
}

bool
TreeSigner::AppendCertificate(const LoggedCertificate &logged_cert) {
  // Serialize for inclusion in the tree.
  string serialized_leaf;
  CHECK_EQ(Serializer::OK, Serializer::SerializeSCTMerkleTreeLeaf(
      logged_cert.sct(), logged_cert.entry(), &serialized_leaf));

  CHECK(logged_cert.has_certificate_sha256_hash());
  // Commit the sequence number of this certificate.
  Database::WriteResult db_result =
      db_->AssignCertificateSequenceNumber(
          logged_cert.certificate_sha256_hash(), cert_tree_.LeafCount());

  if (db_result != Database::OK) {
    CHECK_EQ(Database::SEQUENCE_NUMBER_ALREADY_IN_USE, db_result);
    LOG(ERROR) << "Attempt to assign duplicate sequence number "
               << cert_tree_.LeafCount();
    return false;
  }

  // Update in-memory tree.
  cert_tree_.AddLeaf(serialized_leaf);
  return true;
}

void
TreeSigner::AppendCertificateToTree(const LoggedCertificate &logged_cert) {
  // Serialize for inclusion in the tree.
  string serialized_leaf;
  CHECK_EQ(Serializer::OK, Serializer::SerializeSCTMerkleTreeLeaf(
      logged_cert.sct(), logged_cert.entry(), &serialized_leaf));

  // Update in-memory tree.
  cert_tree_.AddLeaf(serialized_leaf);
}

void TreeSigner::TimestampAndSign(uint64_t min_timestamp, SignedTreeHead *sth) {
  sth->set_version(ct::V1);
  sth->set_root_hash(cert_tree_.CurrentRoot());
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
