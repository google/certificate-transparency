#ifndef CERT_TRANS_LOG_CLUSTER_STATE_CONTROLLER_H_
#define CERT_TRANS_LOG_CLUSTER_STATE_CONTROLLER_H_

#include <condition_variable>
#include <functional>
#include <map>
#include <string>

#include "log/etcd_consistent_store.h"
#include "proto/ct.pb.h"
#include "util/masterelection.h"
#include "util/statusor.h"

namespace cert_trans {


// A class which updates & maintains the states of the individual cluster
// member nodes, and uses this information to determine the overall serving
// state of the cluster.
//
// In particular, this class calculates the optimal STH for the cluster to
// serve at any given time.
template <class Logged>
class ClusterStateController {
 public:
  ClusterStateController(ConsistentStore<Logged>* store,
                         const MasterElection* election,
                         const int min_serving_nodes,
                         const double min_serving_fraction);

  ~ClusterStateController();

  // Updates *this* node's ClusterNodeState to reflect the new STH available.
  void NewTreeHead(const ct::SignedTreeHead& sth);

  // Updates *this* node's ClusterNodeState to reflect the new tree data
  // available.
  void ContiguousTreeSizeUpdated(const int64_t new_contiguous_tree_size);

  // Gets the current (if any) calculated serving STH for the cluster.
  // If there is such an STH then return true and |sth| is populated, returns
  // false otherwise.
  //
  // Note that this simply returns this node's interpretation of the optimum
  // serving STH, the current master/contents of the servingSTH file may
  // differ.
  //
  // Really only intended for testing.
  util::StatusOr<ct::SignedTreeHead> GetCalculatedServingSTH() const;

 private:
  // Updates the representation of *this* node's state in the consistent store.
  void PushLocalNodeState(const std::unique_lock<std::mutex>& lock);

  // Entry point for the watcher callback.
  // Called whenever a node changes its node state.
  void OnClusterStateUpdated(
      const std::vector<Update<ct::ClusterNodeState>>& updates);

  // Calculates the STH which should be served by the cluster, given the
  // current state of the nodes.
  // Returns true iff there currently is a suitable STH.
  bool CalculateServingSTH(const std::unique_lock<std::mutex>& lock);

  // Thread entry point for ServingSTH updater thread.
  void ClusterServingSTHUpdater();

  ConsistentStore<Logged>* const store_;  // Not owned by us
  const MasterElection* const election_;
  const int min_serving_nodes_;
  const double min_serving_fraction_;

  mutable std::mutex mutex_;  // covers the members below:
  ct::ClusterNodeState local_node_state_;
  std::map<std::string, ct::ClusterNodeState> all_node_states_;
  std::unique_ptr<ct::SignedTreeHead> calculated_serving_sth_;
  bool exiting_;
  bool update_required_;
  std::condition_variable update_required_cv_;
  std::thread cluster_serving_sth_update_thread_;

  friend class ClusterStateControllerTest;

  DISALLOW_COPY_AND_ASSIGN(ClusterStateController);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_CLUSTER_STATE_CONTROLLER_H__
