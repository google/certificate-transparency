#include <glog/logging.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>

#include "database.h"
#include "ct.pb.h"
#include "log_lookup.h"
#include "merkle_tree.h"
#include "serializer.h"
#include "types.h"

using ct::LoggedCertificate;
using ct::MerkleAuditProof;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;

LogLookup::LogLookup(const Database *db)
    : db_(db),
      cert_tree_(new Sha256Hasher()),
      latest_tree_head_() {
  Update();
}

LogLookup::~LogLookup() {}

LogLookup::UpdateResult LogLookup::Update() {
  SignedTreeHead sth;

  Database::LookupResult db_result = db_->LatestTreeHead(&sth);
  if (db_result == Database::NOT_FOUND)
    return NO_UPDATES_FOUND;

  CHECK(db_result == Database::LOOKUP_OK);

  if (sth.timestamp() == latest_tree_head_.timestamp())
    return NO_UPDATES_FOUND;

  CHECK(sth.timestamp() > latest_tree_head_.timestamp() &&
        sth.tree_size() >= cert_tree_.LeafCount())
      << "Database replied with an STH that is older than ours: "
      << "Our STH:\n" << latest_tree_head_.DebugString()
      << "Database STH:\n" << sth.DebugString();

  // Record the new hashes: append either all of them, or
  // (if there is an error), none of them.
  std::vector<bstring> new_hashes;
  for (uint64_t sequence_number = cert_tree_.LeafCount();
       sequence_number < sth.tree_size(); ++sequence_number) {
    LoggedCertificate logged_cert;
    // TODO(ekasper): perhaps some of these errors can/should be
    // handled more gracefully. E.g. we could retry a failed update
    // a number of times -- but until we know under which conditions
    // the database might fail (database busy?), just die.
    CHECK_EQ(Database::LOOKUP_OK,
             db_->LookupCertificateByIndex(sequence_number, &logged_cert))
        << "Latest STH has " << sth.tree_size() << "entries but we failed to "
        << "retrieve entry number " << sequence_number;
    CHECK(logged_cert.has_sequence_number())
        << "Logged entry has no sequence number";
    CHECK_EQ(sequence_number, logged_cert.sequence_number());

    bstring new_hash = LeafHash(logged_cert.sct());
    new_hashes.push_back(new_hash);
  }

  // TODO(ekasper): plug in the log public key so that we can verify the STH.
  for (size_t i = 0; i < new_hashes.size(); ++i)
    cert_tree_.AddLeafHash(new_hashes[i]);
  CHECK_EQ(cert_tree_.CurrentRoot(), sth.root_hash())
      << "Computed root hash and stored STH root hash do not match";
  latest_tree_head_.CopyFrom(sth);
  LOG(INFO) << "Found " << new_hashes.size() << " new log entries";
  return UPDATE_OK;
}

// Look up by timestamp + SHA256-hash of the certificate.
LogLookup::LookupResult
LogLookup::CertificateAuditProof(uint64_t timestamp,
                                 const bstring &certificate_hash,
                                 MerkleAuditProof *proof) {
  LoggedCertificate logged_cert;
  Database::LookupResult db_result =
      db_->LookupCertificateByHash(certificate_hash, &logged_cert);
  if (db_result == Database::NOT_FOUND)
    return NOT_FOUND;

  CHECK_EQ(Database::LOOKUP_OK, db_result);

  if (logged_cert.sct().timestamp() != timestamp)
    return NOT_FOUND;

  if (logged_cert.sequence_number() >= cert_tree_.LeafCount())
    // The certificate _is_ logged but we're out of date.
    return NOT_FOUND;

  proof->set_tree_size(cert_tree_.LeafCount());
  proof->set_timestamp(latest_tree_head_.timestamp());
  proof->set_leaf_index(logged_cert.sequence_number());

  proof->clear_path_node();
  std::vector<bstring> audit_path =
      cert_tree_.PathToCurrentRoot(logged_cert.sequence_number() + 1);
  for (size_t i = 0; i < audit_path.size(); ++i)
    proof->add_path_node(audit_path[i]);

  proof->mutable_tree_head_signature()->CopyFrom(latest_tree_head_.signature());
  return OK;
}

bstring LogLookup::LeafHash(const SignedCertificateTimestamp &sct) {
  // Serialize the signed part for inclusion in the tree.
  bstring serialized_sct;
  CHECK_EQ(Serializer::OK,
           Serializer::SerializeSCTForTree(sct, &serialized_sct));
  return cert_tree_.LeafHash(serialized_sct);
}
