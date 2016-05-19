#ifndef CERT_TRANS_LOG_STRICT_CONSISTENT_STORE_INL_H_
#define CERT_TRANS_LOG_STRICT_CONSISTENT_STORE_INL_H_

#include "log/strict_consistent_store.h"

namespace cert_trans {


StrictConsistentStore::StrictConsistentStore(
    const MasterElection* election, ConsistentStore<LoggedEntry>* peer)
    : election_(CHECK_NOTNULL(election)), peer_(CHECK_NOTNULL(peer)) {
}


util::StatusOr<int64_t> StrictConsistentStore::NextAvailableSequenceNumber()
    const {
  if (!election_->IsMaster()) {
    return util::Status(util::error::PERMISSION_DENIED,
                        "Not currently master.");
  }
  return peer_->NextAvailableSequenceNumber();
}


util::Status StrictConsistentStore::SetServingSTH(
    const ct::SignedTreeHead& new_sth) {
  if (!election_->IsMaster()) {
    return util::Status(util::error::PERMISSION_DENIED,
                        "Not currently master.");
  }
  return peer_->SetServingSTH(new_sth);
}


util::Status StrictConsistentStore::UpdateSequenceMapping(
    EntryHandle<ct::SequenceMapping>* entry) {
  if (!election_->IsMaster()) {
    return util::Status(util::error::PERMISSION_DENIED,
                        "Not currently master.");
  }
  return peer_->UpdateSequenceMapping(entry);
}


util::Status StrictConsistentStore::SetClusterConfig(
    const ct::ClusterConfig& config) {
  if (!election_->IsMaster()) {
    return util::Status(util::error::PERMISSION_DENIED,
                        "Not currently master.");
  }
  return peer_->SetClusterConfig(config);
}


util::StatusOr<int64_t> StrictConsistentStore::CleanupOldEntries() {
  if (!election_->IsMaster()) {
    return util::Status(util::error::PERMISSION_DENIED,
                        "Not currently master.");
  }
  return peer_->CleanupOldEntries();
}


}  // namespace cert_trans


#endif  // CERT_TRANS_LOG_STRICT_CONSISTENT_STORE_INL_H_
