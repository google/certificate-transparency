#include "log/strict_consistent_store.h"

using ct::SignedTreeHead;
using util::Status;
using util::StatusOr;

namespace cert_trans {


StrictConsistentStore::StrictConsistentStore(const MasterElection* election,
                                             ConsistentStore* peer)
    : election_(CHECK_NOTNULL(election)), peer_(CHECK_NOTNULL(peer)) {
}


StatusOr<int64_t> StrictConsistentStore::NextAvailableSequenceNumber() const {
  if (!election_->IsMaster()) {
    return Status(util::error::PERMISSION_DENIED, "Not currently master.");
  }
  return peer_->NextAvailableSequenceNumber();
}


Status StrictConsistentStore::SetServingSTH(const SignedTreeHead& new_sth) {
  if (!election_->IsMaster()) {
    return Status(util::error::PERMISSION_DENIED, "Not currently master.");
  }
  return peer_->SetServingSTH(new_sth);
}


Status StrictConsistentStore::UpdateSequenceMapping(
    EntryHandle<ct::SequenceMapping>* entry) {
  if (!election_->IsMaster()) {
    return Status(util::error::PERMISSION_DENIED, "Not currently master.");
  }
  return peer_->UpdateSequenceMapping(entry);
}


Status StrictConsistentStore::SetClusterConfig(
    const ct::ClusterConfig& config) {
  if (!election_->IsMaster()) {
    return Status(util::error::PERMISSION_DENIED, "Not currently master.");
  }
  return peer_->SetClusterConfig(config);
}


StatusOr<int64_t> StrictConsistentStore::CleanupOldEntries() {
  if (!election_->IsMaster()) {
    return Status(util::error::PERMISSION_DENIED, "Not currently master.");
  }
  return peer_->CleanupOldEntries();
}


}  // namespace cert_trans
