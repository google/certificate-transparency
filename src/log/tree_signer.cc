#include <set>
#include <stdint.h>

#include "database.h"
#include "log_signer.h"
#include "merkle_tree.h"
#include "tree_signer.h"
#include "serializer.h"
#include "types.h"
#include "util.h"

using ct::LoggedCertificate;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;

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

TreeSigner::UpdateResult TreeSigner::UpdateTree() {
  // Check that the latest sth is ours.
  SignedTreeHead sth;
  Database::LookupResult db_result = db_->LatestTreeHead(&sth);

  if ((LastUpdateTime() == 0 && db_result != Database::NOT_FOUND) ||
      (LastUpdateTime() > 0 &&
       (db_result != Database::LOOKUP_OK ||
        sth.timestamp() != latest_tree_head_.timestamp() ||
        sth.tree_size() != latest_tree_head_.tree_size() ||
        sth.root_hash() != latest_tree_head_.root_hash())))
    return DB_ERROR;

  // Timestamps have to be unique.
  uint64_t min_timestamp = sth.timestamp() + 1;

  std::set<bstring> pending_hashes = db_->PendingHashes();
  std::set<bstring>::const_iterator it;
  for (it = pending_hashes.begin(); it != pending_hashes.end(); ++it) {
    LoggedCertificate logged_cert;
    db_result = db_->LookupCertificateByHash(*it, &logged_cert);
    if (db_result != Database::LOOKUP_OK || logged_cert.has_sequence_number() ||
        !AppendCertificate(*it, logged_cert.sct()))
      return DB_ERROR;

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
  Database::WriteResult write_result = db_->WriteTreeHead(new_sth);
  if (write_result != Database::OK)
    return DB_ERROR;
  latest_tree_head_.CopyFrom(new_sth);
  return OK;
}

void TreeSigner::BuildTree() {
  // Read the latest sth.
  SignedTreeHead sth;
  Database::LookupResult db_result = db_->LatestTreeHead(&sth);
  if (db_result != Database::LOOKUP_OK && db_result != Database::NOT_FOUND)
    abort();

  if (db_result == Database::LOOKUP_OK) {
    // If the timestamp is from the future, then either the database is corrupt
    // or our clock is corrupt; either way we shouldn't be signing things.
    if (sth.timestamp() > util::TimeInMilliseconds())
      abort();

    // Read all logged and signed entries.
    for (size_t i = 0; i < sth.tree_size(); ++i) {
      LoggedCertificate logged_cert;
      db_result = db_->LookupCertificateByIndex(i, &logged_cert);
      if (db_result != Database::LOOKUP_OK ||
          logged_cert.sct().timestamp() > sth.timestamp() ||
          logged_cert.sequence_number() != i ||
          !AppendCertificateToTree(logged_cert.sct()))
        abort();
    }

    // Check the root hash.
    if (cert_tree_.CurrentRoot() != sth.root_hash())
      abort();

    latest_tree_head_.CopyFrom(sth);
  }

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
    if (db_result != Database::LOOKUP_OK ||
        logged_cert.sequence_number() != i ||
        !AppendCertificateToTree(logged_cert.sct()))
      abort();
  }
}

bool
TreeSigner::AppendCertificate(const bstring &key,
                              const SignedCertificateTimestamp &sct) {
  // Serialize for inclusion in the tree.
  bstring serialized_sct;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeSCTForTree(sct, &serialized_sct);
  if (serialize_result != Serializer::OK)
    return false;

  // Commit the sequence number of this certificate.
  Database::WriteResult db_write =
      db_->AssignCertificateSequenceNumber(key, cert_tree_.LeafCount());
  if (db_write != Database::OK)
    return false;

  // Update in-memory tree.
  cert_tree_.AddLeaf(serialized_sct);
  return true;
}

bool
TreeSigner::AppendCertificateToTree(const SignedCertificateTimestamp &sct) {
  // Serialize for inclusion in the tree.
  bstring serialized_sct;
  Serializer::SerializeResult serialize_result =
      Serializer::SerializeSCTForTree(sct, &serialized_sct);
  if (serialize_result != Serializer::OK)
    return false;

  // Update in-memory tree.
  cert_tree_.AddLeaf(serialized_sct);
  return true;
}

void TreeSigner::TimestampAndSign(uint64_t min_timestamp, SignedTreeHead *sth) {
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
