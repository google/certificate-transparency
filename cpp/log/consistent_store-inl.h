#include "log/consistent_store.h"

using ct::ClusterNodeState;
using ct::SignedTreeHead;
using std::lock_guard;
using std::mutex;
using std::vector;

namespace cert_trans {

template <class Logged>
void ConsistentStore<Logged>::WatchServingSTH(const ServingSTHCallback& cb) {
  lock_guard<mutex> lock(watcher_mutex_);
  sth_watchers_.push_back(cb);
}


template <class Logged>
void ConsistentStore<Logged>::WatchClusterNodeStates(
    const ClusterNodeStateCallback& cb) {
  lock_guard<mutex> lock(watcher_mutex_);
  cluster_node_watchers_.push_back(cb);
}


template <class Logged>
void ConsistentStore<Logged>::OnServingSTHUpdate(
    const Update<ct::SignedTreeHead>& update) {
  lock_guard<mutex> lock(watcher_mutex_);
  for (const auto& c : sth_watchers_) {
    c(update);
  }
}


template <class Logged>
void ConsistentStore<Logged>::OnClusterNodeStatesUpdate(
    const vector<Update<ClusterNodeState>>& updates) {
  lock_guard<mutex> lock(watcher_mutex_);
  for (const auto& c : cluster_node_watchers_) {
    c(updates);
  }
}


}  // namespace cert_trans
