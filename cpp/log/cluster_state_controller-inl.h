#ifndef CERT_TRANS_LOG_CLUSTER_STATE_CONTROLLER_INL_H_
#define CERT_TRANS_LOG_CLUSTER_STATE_CONTROLLER_INL_H_

#include "log/cluster_state_controller.h"

#include <functional>

#include "log/etcd_consistent_store-inl.h"
#include "proto/ct.pb.h"

namespace cert_trans {


template <class Logged>
ClusterStateController<Logged>::ClusterStateController(
    ConsistentStore<Logged>* store, const MasterElection* election,
    const int min_serving_nodes, const double min_serving_fraction)
    : store_(CHECK_NOTNULL(store)),
      election_(CHECK_NOTNULL(election)),
      min_serving_nodes_(min_serving_nodes),
      min_serving_fraction_(min_serving_fraction),
      exiting_(false),
      update_required_(false),
      cluster_serving_sth_update_thread_(
          std::bind(&ClusterStateController<Logged>::ClusterServingSTHUpdater,
                    this)) {
  CHECK_LE(1, min_serving_nodes_);
  CHECK_LT(0, min_serving_fraction_);
  store_->WatchClusterNodeStates(
      std::bind(&ClusterStateController::OnClusterStateUpdated, this,
                std::placeholders::_1));
}


template <class Logged>
ClusterStateController<Logged>::~ClusterStateController() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    exiting_ = true;
  }
  update_required_cv_.notify_all();
  cluster_serving_sth_update_thread_.join();
}


template <class Logged>
void ClusterStateController<Logged>::NewTreeHead(
    const ct::SignedTreeHead& sth) {
  std::unique_lock<std::mutex> lock(mutex_);
  if (local_node_state_.has_newest_sth()) {
    CHECK_GE(sth.timestamp(), local_node_state_.newest_sth().timestamp());
  }
  local_node_state_.mutable_newest_sth()->CopyFrom(sth);
  PushLocalNodeState(lock);
}


template <class Logged>
void ClusterStateController<Logged>::ContiguousTreeSizeUpdated(
    const int64_t new_contiguous_tree_size) {
  CHECK_GE(new_contiguous_tree_size, 0);
  std::unique_lock<std::mutex> lock(mutex_);
  CHECK_GE(new_contiguous_tree_size, local_node_state_.contiguous_tree_size());
  local_node_state_.set_contiguous_tree_size(new_contiguous_tree_size);
  PushLocalNodeState(lock);
}


template <class Logged>
util::StatusOr<ct::SignedTreeHead>
ClusterStateController<Logged>::GetCalculatedServingSTH() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!calculated_serving_sth_) {
    return util::StatusOr<ct::SignedTreeHead>(
        util::Status(util::error::NOT_FOUND, "No calculated STH"));
  }
  return util::StatusOr<ct::SignedTreeHead>(*calculated_serving_sth_);
}


template <class Logged>
void ClusterStateController<Logged>::PushLocalNodeState(
    const std::unique_lock<std::mutex>& lock) {
  CHECK(lock.owns_lock());
  const util::Status status(store_->SetClusterNodeState(local_node_state_));
  if (!status.ok()) {
    LOG(WARNING) << status;
  }
}


template <class Logged>
void ClusterStateController<Logged>::OnClusterStateUpdated(
    const std::vector<Update<ct::ClusterNodeState>>& updates) {
  std::unique_lock<std::mutex> lock(mutex_);
  for (const auto& update : updates) {
    const std::string& node_id(update.handle_.Entry().node_id());
    if (update.exists_) {
      all_node_states_[node_id] = update.handle_.Entry();
    } else {
      CHECK_EQ(1, all_node_states_.erase(node_id));
    }
  }

  if (CalculateServingSTH(lock) && election_->IsMaster()) {
    update_required_ = true;
    lock.unlock();
    update_required_cv_.notify_all();
  }
}


template <class Logged>
bool ClusterStateController<Logged>::CalculateServingSTH(
    const std::unique_lock<std::mutex>& lock) {
  VLOG(1) << "Calculating new ServingSTH...";
  CHECK(lock.owns_lock());

  // First, create a mapping of tree size to number of nodes at that size, and
  // a mapping of the newst STH for any given size:
  std::map<int64_t, ct::SignedTreeHead> sth_by_size;
  std::map<int64_t, int> num_nodes_by_sth_size;
  for (const auto& node : all_node_states_) {
    if (node.second.has_newest_sth()) {
      const int64_t tree_size(node.second.newest_sth().tree_size());
      CHECK_LE(0, tree_size);
      num_nodes_by_sth_size[tree_size]++;
      // Default timestamp (first call in here) will be 0
      if (node.second.newest_sth().timestamp() >
          sth_by_size[tree_size].timestamp()) {
        sth_by_size[tree_size] = node.second.newest_sth();
      }
    }
  }

  // Next calculate the newest STH we've seen which satisfies the following
  // criteria:
  //   - at least min_serving_nodes_ have an STH at least as large
  //   - at least min_serving_fraction_ have an STH at least as large
  //   - not smaller than the current serving STH
  int num_nodes_seen(0);
  const int current_tree_size(
      calculated_serving_sth_ ? calculated_serving_sth_->tree_size() : 0);
  CHECK_LE(0, current_tree_size);

  // Work backwards (from largest STH size) until we see that there's enough
  // coverage (according to the criteria above) to serve an STH (or determine
  // that there are insufficient nodes to serve anything.)
  for (auto it = num_nodes_by_sth_size.rbegin();
       it != num_nodes_by_sth_size.rend() && it->first >= current_tree_size;
       ++it) {
    // num_nodes_seen keeps track of the number of nodes we've seen so far (and
    // since we're working from larger to smaller size STH, they should all be
    // able to serve this [and smaller] STHs.)
    num_nodes_seen += it->second;
    const double serving_fraction(static_cast<double>(num_nodes_seen) /
                                  all_node_states_.size());
    if (serving_fraction >= min_serving_fraction_ &&
        num_nodes_seen >= min_serving_nodes_) {
      LOG(INFO) << "Can serve @" << it->first << " with " << num_nodes_seen
                << " nodes (" << (serving_fraction * 100) << "% of cluster)";
      calculated_serving_sth_.reset(
          new ct::SignedTreeHead(sth_by_size[it->first]));
      return true;
    }
  }
  // TODO(alcutter): Add a mechanism to take the cluster off-line until we have
  // sufficient nodes able to serve.
  LOG(WARNING) << "Failed to determine suitable serving STH.";
  return false;
}


// Thread entry point for cluster_serving_sth_update_thread_.
template <class Logged>
void ClusterStateController<Logged>::ClusterServingSTHUpdater() {
  while (true) {
    std::unique_lock<std::mutex> lock(mutex_);
    update_required_cv_.wait(lock, [this]() {
      return update_required_ || exiting_;
    });
    if (exiting_) {
      return;
    }
    CHECK(update_required_);
    CHECK_NOTNULL(calculated_serving_sth_.get());
    const ct::SignedTreeHead local_sth(*calculated_serving_sth_);

    update_required_ = false;

    // And then release it before we send the update.
    // This allows any other code to get on with modifying
    // calculated_serving_sth_ in response to cluster state changes
    lock.unlock();

    if (election_->IsMaster()) {
      store_->SetServingSTH(local_sth);
    }
  }
}


}  // namespace cert_trans


#endif  // CERT_TRANS_LOG_CLUSTER_STATE_CONTROLLER_INL_H_
