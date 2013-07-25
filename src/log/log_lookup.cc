/* -*- indent-tabs-mode: nil -*- */
#include <glog/logging.h>
#include <map>
#include <stdint.h>
#include <stdlib.h>

#include "log/database.h"
#include "log/log_lookup.h"
#include "merkletree/merkle_tree.h"
#include "merkletree/serial_hasher.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"

using ct::MerkleAuditProof;
using ct::ShortMerkleAuditProof;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;
using std::string;

template <class Logged> LogLookup<Logged>::LogLookup(const Database<Logged> *db)
    : db_(db),
      cert_tree_(new Sha256Hasher()),
      latest_tree_head_() {
  Update();
}

template <class Logged> LogLookup<Logged>::~LogLookup() {}

template <class Logged> typename LogLookup<Logged>::UpdateResult
LogLookup<Logged>::Update() {
  SignedTreeHead sth;

  typename Database<Logged>::LookupResult db_result = db_->LatestTreeHead(&sth);
  if (db_result == Database<Logged>::NOT_FOUND)
    return NO_UPDATES_FOUND;

  CHECK(db_result == Database<Logged>::LOOKUP_OK);
  CHECK_EQ(ct::V1, sth.version())
      << "Tree head signed with an unknown version";

  if (sth.timestamp() == latest_tree_head_.timestamp())
    return NO_UPDATES_FOUND;

  CHECK(sth.timestamp() > latest_tree_head_.timestamp() &&
        sth.tree_size() >= cert_tree_.LeafCount())
      << "Database replied with an STH that is older than ours: "
      << "Our STH:\n" << latest_tree_head_.DebugString()
      << "Database STH:\n" << sth.DebugString();

  // Record the new hashes: append all of them, die on any error.
  // TODO(ekasper): make tree signer write leaves out to the database,
  // so that we don't have to read the entries in.
  string leaf_hash;
  for (uint64_t sequence_number = cert_tree_.LeafCount();
       sequence_number < sth.tree_size(); ++sequence_number) {
    Logged logged;
    // TODO(ekasper): perhaps some of these errors can/should be
    // handled more gracefully. E.g. we could retry a failed update
    // a number of times -- but until we know under which conditions
    // the database might fail (database busy?), just die.
    CHECK_EQ(Database<Logged>::LOOKUP_OK,
             db_->LookupByIndex(sequence_number, &logged))
        << "Latest STH has " << sth.tree_size() << "entries but we failed to "
        << "retrieve entry number " << sequence_number;
    CHECK(logged.has_sequence_number())
        << "Logged entry has no sequence number";
    CHECK_EQ(sequence_number, logged.sequence_number());

    leaf_hash = LeafHash(logged);
    // TODO(ekasper): plug in the log public key so that we can verify the STH.
    CHECK_EQ(sequence_number + 1, cert_tree_.AddLeafHash(leaf_hash));
    // Duplicate leaves shouldn't really happen but are not a problem either:
    // we just return the Merkle proof of the first occurrence.
    leaf_index_.insert(std::pair<string, uint64_t>(leaf_hash,
                                                   sequence_number));
  }
  CHECK_EQ(cert_tree_.CurrentRoot(), sth.root_hash())
      << "Computed root hash and stored STH root hash do not match";
  LOG(INFO) << "Found " << sth.tree_size() - latest_tree_head_.tree_size()
            << " new log entries";
  latest_tree_head_.CopyFrom(sth);
  return UPDATE_OK;
}

// Look up by SHA256-hash of the certificate.
template <class Logged> typename LogLookup<Logged>::LookupResult
LogLookup<Logged>::AuditProof(const string &merkle_leaf_hash,
                              MerkleAuditProof *proof) {
  std::map<string, uint64_t>::const_iterator it =
      leaf_index_.find(merkle_leaf_hash);
  if (it == leaf_index_.end())
    return NOT_FOUND;

  uint64_t leaf_index = it->second;

  proof->set_version(ct::V1);
  proof->set_tree_size(cert_tree_.LeafCount());
  proof->set_timestamp(latest_tree_head_.timestamp());
  proof->set_leaf_index(leaf_index);

  proof->clear_path_node();
  std::vector<string> audit_path =
      cert_tree_.PathToCurrentRoot(leaf_index + 1);
  for (size_t i = 0; i < audit_path.size(); ++i)
    proof->add_path_node(audit_path[i]);

  proof->mutable_id()->CopyFrom(latest_tree_head_.id());
  proof->mutable_tree_head_signature()->CopyFrom(latest_tree_head_.signature());
  return OK;
}

// Look up by SHA256-hash of the certificate and tree size.
template <class Logged> typename LogLookup<Logged>::LookupResult
LogLookup<Logged>::AuditProof(const string &merkle_leaf_hash, size_t tree_size,
                              ShortMerkleAuditProof *proof) {
  std::map<string, uint64_t>::const_iterator it =
      leaf_index_.find(merkle_leaf_hash);
  if (it == leaf_index_.end())
    return NOT_FOUND;

  uint64_t leaf_index = it->second;

  proof->set_leaf_index(leaf_index);

  proof->clear_path_node();
  std::vector<string> audit_path =
      cert_tree_.PathToRootAtSnapshot(leaf_index + 1, tree_size);
  for (size_t i = 0; i < audit_path.size(); ++i)
    proof->add_path_node(audit_path[i]);

  return OK;
}

template <class Logged> string
LogLookup<Logged>::LeafHash(const Logged &logged) {
  string serialized_leaf;
  CHECK(logged.SerializeForLeaf(&serialized_leaf));
  return cert_tree_.LeafHash(serialized_leaf);
}
