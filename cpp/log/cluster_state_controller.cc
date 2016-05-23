#include "log/cluster_state_controller.h"

#include <stdint.h>
#include <functional>

#include "fetcher/peer.h"
#include "log/database.h"
#include "log/etcd_consistent_store.h"
#include "monitoring/monitoring.h"
#include "proto/ct.pb.h"

using ct::ClusterConfig;
using ct::ClusterNodeState;
using ct::SignedTreeHead;
using std::bind;
using std::lock_guard;
using std::make_pair;
using std::make_shared;
using std::map;
using std::mutex;
using std::pair;
using std::placeholders::_1;
using std::shared_ptr;
using std::string;
using std::to_string;
using std::unique_lock;
using std::unique_ptr;
using std::vector;
using util::Executor;
using util::Status;
using util::StatusOr;

namespace cert_trans {
namespace {


Gauge<>* serving_tree_size =
    Gauge<>::New("serving_tree_size", "Size of the current serving STH");

Gauge<>* serving_tree_timestamp =
    Gauge<>::New("serving_tree_timestamp",
                 "Timestamp of the current serving STH");


unique_ptr<AsyncLogClient> BuildAsyncLogClient(
    const shared_ptr<libevent::Base>& base, UrlFetcher* fetcher,
    const ClusterNodeState& state) {
  CHECK(!state.hostname().empty());
  CHECK_GT(state.log_port(), 0);
  CHECK_LE(state.log_port(), UINT16_MAX);

  // TODO(pphaneuf): We'd like to support HTTPS at some point.
  return unique_ptr<AsyncLogClient>(new AsyncLogClient(
      base.get(), fetcher,
      "http://" + state.hostname() + ":" + to_string(state.log_port())));
}


}  // namespace


ClusterStateController::ClusterPeer::ClusterPeer(
    const shared_ptr<libevent::Base>& base, UrlFetcher* fetcher,
    const ClusterNodeState& state)
    : Peer(BuildAsyncLogClient(base, fetcher, state)), state_(state) {
}


int64_t ClusterStateController::ClusterPeer::TreeSize() const {
  lock_guard<mutex> lock(lock_);
  return state_.newest_sth().tree_size();
}


void ClusterStateController::ClusterPeer::UpdateClusterNodeState(
    const ClusterNodeState& new_state) {
  lock_guard<mutex> lock(lock_);
  // TODO(pphaneuf): We have no way of changing the AsyncLogClient in
  // our parent, maybe we should?
  CHECK_EQ(state_.hostname(), new_state.hostname());
  CHECK_EQ(state_.log_port(), new_state.log_port());
  state_ = new_state;
}


ClusterNodeState ClusterStateController::ClusterPeer::state() const {
  lock_guard<mutex> lock(lock_);
  return state_;
}


pair<string, int> ClusterStateController::ClusterPeer::GetHostPort() const {
  lock_guard<mutex> lock(lock_);
  return make_pair(state_.hostname(), state_.log_port());
}


// TODO(alcutter): Need a better system for hanging tasks onto events,
// Pierre's task-a-palooza idea perhaps?
ClusterStateController::ClusterStateController(
    Executor* executor, const shared_ptr<libevent::Base>& base,
    UrlFetcher* url_fetcher, Database* database, ConsistentStore* store,
    MasterElection* election, ContinuousFetcher* fetcher)
    : base_(base),
      url_fetcher_(CHECK_NOTNULL(url_fetcher)),
      database_(CHECK_NOTNULL(database)),
      store_(CHECK_NOTNULL(store)),
      election_(CHECK_NOTNULL(election)),
      fetcher_(CHECK_NOTNULL(fetcher)),
      watch_config_task_(CHECK_NOTNULL(executor)),
      watch_node_states_task_(CHECK_NOTNULL(executor)),
      watch_serving_sth_task_(CHECK_NOTNULL(executor)),
      exiting_(false),
      update_required_(false),
      cluster_serving_sth_update_thread_(
          bind(&ClusterStateController::ClusterServingSTHUpdater, this)) {
  CHECK_NOTNULL(base_.get());
  store_->WatchClusterNodeStates(
      bind(&ClusterStateController::OnClusterStateUpdated, this, _1),
      watch_node_states_task_.task());
  store_->WatchClusterConfig(
      bind(&ClusterStateController::OnClusterConfigUpdated, this, _1),
      watch_config_task_.task());
  store_->WatchServingSTH(bind(&ClusterStateController::OnServingSthUpdated,
                               this, _1),
                          watch_serving_sth_task_.task());
}


ClusterStateController::~ClusterStateController() {
  watch_config_task_.Cancel();
  watch_node_states_task_.Cancel();
  watch_serving_sth_task_.Cancel();
  {
    lock_guard<mutex> lock(mutex_);
    exiting_ = true;
  }
  update_required_cv_.notify_all();
  cluster_serving_sth_update_thread_.join();
  watch_config_task_.Wait();
  watch_node_states_task_.Wait();
  watch_serving_sth_task_.Wait();
}


void ClusterStateController::NewTreeHead(const SignedTreeHead& sth) {
  unique_lock<mutex> lock(mutex_);
  SignedTreeHead db_sth;
  const Database::LookupResult result(database_->LatestTreeHead(&db_sth));

  const bool serving_sth_newer_than_db_sth(
      actual_serving_sth_ &&
      ((result == Database::LOOKUP_OK &&
        db_sth.tree_size() <= actual_serving_sth_->tree_size() &&
        db_sth.timestamp() < actual_serving_sth_->timestamp()) ||
       (result == Database::NOT_FOUND)));

  // Check whether this updated tree head would enable us to start serving the
  // current cluster serving STH. If so, we'll store it to the local DB below.
  const bool write_sth(serving_sth_newer_than_db_sth &&
                       sth.tree_size() >= actual_serving_sth_->tree_size());

  if (local_node_state_.has_newest_sth()) {
    CHECK_GE(sth.timestamp(), local_node_state_.newest_sth().timestamp());
  }
  local_node_state_.mutable_newest_sth()->CopyFrom(sth);
  PushLocalNodeState(lock);

  SignedTreeHead sth_to_write;
  if (write_sth) {
    sth_to_write = *actual_serving_sth_;
  }

  // Updating the tree below can take a while if the tree delta is large and
  // the DB is under load (e.g. due to fetcher / external traffic), the tree
  // itself is locked during this process so we can release our lock here to
  // not block other operations (e.g. watchdog operations.)
  lock.unlock();

  if (write_sth) {
    // TODO(alcutter): Perhaps we need to know about updates to the contiguous
    // tree size in the DB again, so that we can write this out as soon as
    // we're able to serve it.
    CHECK_EQ(Database::OK, database_->WriteTreeHead(sth_to_write));
  }
}


StatusOr<SignedTreeHead> ClusterStateController::GetCalculatedServingSTH()
    const {
  lock_guard<mutex> lock(mutex_);
  if (!calculated_serving_sth_) {
    return Status(util::error::NOT_FOUND, "No calculated STH");
  }
  return *calculated_serving_sth_;
}


void ClusterStateController::GetLocalNodeState(ClusterNodeState* state) const {
  CHECK_NOTNULL(state);
  lock_guard<mutex> lock(mutex_);
  *state = local_node_state_;
}


void ClusterStateController::SetNodeHostPort(const string& host,
                                             const uint16_t port) {
  unique_lock<mutex> lock(mutex_);
  local_node_state_.set_hostname(host);
  local_node_state_.set_log_port(port);
  PushLocalNodeState(lock);
}


void ClusterStateController::RefreshNodeState() {
  unique_lock<mutex> lock(mutex_);
  PushLocalNodeState(lock);
}


bool ClusterStateController::NodeIsStale() const {
  lock_guard<mutex> lock(mutex_);
  if (!actual_serving_sth_) {
    return true;
  }
  return database_->TreeSize() < actual_serving_sth_->tree_size();
}


vector<ClusterNodeState> ClusterStateController::GetFreshNodes() const {
  lock_guard<mutex> lock(mutex_);
  if (!actual_serving_sth_) {
    LOG(WARNING) << "Cluster has no ServingSTH, all nodes are stale.";
    return {};
  }
  vector<ClusterNodeState> fresh;  // for 1983.
  // Here we go:
  for (const auto& node : all_peers_) {
    const bool is_self(
        node.second->state().hostname() == local_node_state_.hostname() &&
        node.second->state().log_port() == local_node_state_.log_port());
    if (!is_self && node.second->state().has_newest_sth() &&
        node.second->state().newest_sth().tree_size() >=
            actual_serving_sth_->tree_size()) {
      VLOG(1) << "Node is fresh: " << node.second->state().node_id();
      fresh.push_back(node.second->state());
    }
  }
  return fresh;
}


void ClusterStateController::PushLocalNodeState(
    const unique_lock<mutex>& lock) {
  CHECK(lock.owns_lock());

  const Status status(store_->SetClusterNodeState(local_node_state_));
  LOG_IF(WARNING, !status.ok()) << "Couldn't set ClusterNodeState: " << status;
}


void ClusterStateController::OnClusterStateUpdated(
    const vector<Update<ClusterNodeState>>& updates) {
  unique_lock<mutex> lock(mutex_);
  for (const auto& update : updates) {
    const string& node_id(update.handle_.Key());
    if (update.exists_) {
      auto it(all_peers_.find(node_id));
      VLOG_IF(1, it == all_peers_.end()) << "Node joined: " << node_id;

      // If the host or port change, remove the ClusterPeer, so that
      // we re-create it.
      if (it != all_peers_.end() &&
          it->second->GetHostPort() !=
              make_pair(update.handle_.Entry().hostname(),
                        update.handle_.Entry().log_port())) {
        all_peers_.erase(it);
        it = all_peers_.end();
      }

      if (it != all_peers_.end()) {
        it->second->UpdateClusterNodeState(update.handle_.Entry());
      } else {
        const shared_ptr<ClusterPeer> peer(
            make_shared<ClusterPeer>(base_, url_fetcher_,
                                     update.handle_.Entry()));
        // TODO(pphaneuf): all_peers_ and fetcher_ both maintain a
        // list of cluster members, this should be split off into its
        // own class, and share an instance between the interested
        // parties.
        all_peers_.emplace(node_id, peer);
        fetcher_->AddPeer(node_id, peer);
      }
    } else {
      VLOG(1) << "Node left: " << node_id;
      CHECK_EQ(static_cast<size_t>(1), all_peers_.erase(node_id));
      fetcher_->RemovePeer(node_id);
    }
  }

  CalculateServingSTH(lock);
}


void ClusterStateController::OnClusterConfigUpdated(
    const Update<ClusterConfig>& update) {
  unique_lock<mutex> lock(mutex_);
  if (!update.exists_) {
    LOG(WARNING) << "No ClusterConfig exists.";
    return;
  }

  cluster_config_ = update.handle_.Entry();
  LOG(INFO) << "Received new ClusterConfig:\n"
            << cluster_config_.DebugString();

  // May need to re-calculate the servingSTH since the ClusterConfig has
  // changed:
  CalculateServingSTH(lock);
}


void ClusterStateController::OnServingSthUpdated(
    const Update<SignedTreeHead>& update) {
  unique_lock<mutex> lock(mutex_);
  bool write_sth(true);

  if (!update.exists_) {
    LOG(WARNING) << "Cluster has no Serving STH!";
    actual_serving_sth_.reset();
    write_sth = false;
  } else {
    // TODO(alcutter): Validate STH and verify consistency with whatever we've
    // already got locally.
    if (update.handle_.Entry().timestamp() == 0) {
      LOG(WARNING) << "Ignoring invalid Serving STH update.";
      return;
    }

    actual_serving_sth_.reset(new SignedTreeHead(update.handle_.Entry()));
    LOG(INFO) << "Received new Serving STH: "
              << actual_serving_sth_->ShortDebugString();
    serving_tree_size->Set(actual_serving_sth_->tree_size());
    serving_tree_timestamp->Set(actual_serving_sth_->timestamp());

    // Double check this STH is newer than, or idential to, what we have in
    // the database. (It definitely should be!)
    SignedTreeHead db_sth;
    const Database::LookupResult lookup_result(
        database_->LatestTreeHead(&db_sth));
    switch (lookup_result) {
      case Database::LOOKUP_OK:
        VLOG(1) << "Local latest STH:\n" << db_sth.DebugString();
        // Check it's for the same log:
        CHECK_EQ(actual_serving_sth_->id().key_id(), db_sth.id().key_id());
        CHECK_EQ(actual_serving_sth_->version(), db_sth.version());

        if (db_sth.timestamp() == actual_serving_sth_->timestamp()) {
          // Either this STH is *identical* to the latest one we have in the DB
          CHECK_EQ(actual_serving_sth_->tree_size(), db_sth.tree_size());
          CHECK_EQ(actual_serving_sth_->sha256_root_hash(),
                   db_sth.sha256_root_hash());
          // In which case there's no need to write this to the DB because we
          // already have it.
          write_sth = false;
        } else {
          // Or it's strictly newer:
          CHECK_GT(actual_serving_sth_->timestamp(), db_sth.timestamp());
          CHECK_GE(actual_serving_sth_->tree_size(), db_sth.tree_size());
        }
        break;
      case Database::NOT_FOUND:
        LOG(WARNING) << "Local DB doesn't have any STH, new node?";
        break;
      default:
        LOG(FATAL) << "Problem looking up local DB's latest STH.";
    }

    if (database_->TreeSize() < actual_serving_sth_->tree_size()) {
      LOG(INFO) << "Local node doesn't yet have all entries for "
                << "serving STH, not writing to DB.";
      write_sth = false;
    }
  }

  SignedTreeHead sth_to_write;
  if (write_sth) {
    sth_to_write = *actual_serving_sth_;
  }

  lock.unlock();

  if (write_sth) {
    // All good, write this STH to our local DB:
    CHECK_EQ(Database::OK, database_->WriteTreeHead(sth_to_write));
  }
}


void ClusterStateController::CalculateServingSTH(
    const unique_lock<mutex>& lock) {
  VLOG(1) << "Calculating new ServingSTH...";
  CHECK(lock.owns_lock());

  // First, create a mapping of tree size to number of nodes at that size, and
  // a mapping of the newst STH for any given size:
  map<int64_t, SignedTreeHead> sth_by_size;
  map<int64_t, int> num_nodes_by_sth_size;
  for (const auto& node : all_peers_) {
    const ClusterNodeState node_state(node.second->state());
    if (node_state.has_newest_sth()) {
      const int64_t tree_size(node_state.newest_sth().tree_size());
      CHECK_LE(0, tree_size);
      const int64_t timestamp(node_state.newest_sth().timestamp());
      CHECK_LE(0, timestamp);

      num_nodes_by_sth_size[tree_size]++;

      // Default timestamp (first call in here) will be 0
      if (node_state.newest_sth().timestamp() >
          sth_by_size[tree_size].timestamp()) {
        sth_by_size[tree_size] = node_state.newest_sth();
      }
    }
  }

  // Next calculate the newest STH we've seen which satisfies the following
  // criteria:
  //   - at least minimum_serving_nodes have an STH at least as large
  //   - at least minimum_serving_fraction have an STH at least as large
  //   - not smaller than the current serving STH
  //   - has a timestamp higher than the current serving STH
  int num_nodes_seen(0);
  const int current_tree_size(
      calculated_serving_sth_ ? calculated_serving_sth_->tree_size() : 0);
  CHECK_LE(0, current_tree_size);

  bool candidates_include_current(false);
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
                                  all_peers_.size());
    if (serving_fraction >= cluster_config_.minimum_serving_fraction() &&
        num_nodes_seen >= cluster_config_.minimum_serving_nodes()) {
      const SignedTreeHead& candidate_sth(sth_by_size[it->first]);

      // This STH isn't a viable candidate unless its timestamp is strictly
      // newer than any current serving STH:
      if (actual_serving_sth_ &&
          candidate_sth.timestamp() <= actual_serving_sth_->timestamp()) {
        VLOG(1) << "Discarding candidate STH:\n" << candidate_sth.DebugString()
                << "\nbecause its timestamp is <= current serving STH "
                << "timestamp (" << actual_serving_sth_->timestamp() << ")";
        candidates_include_current |= candidate_sth.SerializeAsString() ==
                                      actual_serving_sth_->SerializeAsString();
        continue;
      }

      LOG(INFO) << "Can serve @" << it->first << " with " << num_nodes_seen
                << " nodes (" << (serving_fraction * 100) << "% of cluster)";
      calculated_serving_sth_.reset(
          new SignedTreeHead(sth_by_size[it->first]));
      // Push this STH out to the cluster if we're master:
      if (election_->IsMaster()) {
        VLOG(1) << "Pushing new STH out to cluster";
        update_required_ = true;
        update_required_cv_.notify_all();
      } else {
        VLOG(1) << "Not pushing new STH to cluster since we're not the master";
      }
      return;
    }
  }
  // TODO(alcutter): Add a mechanism to take the cluster off-line until we have
  // sufficient nodes able to serve.
  if (!candidates_include_current) {
    LOG(WARNING) << "Failed to determine suitable serving STH.";
  } else {
    VLOG(1) << "Continuing to serve previous STH.";
  }
}


// Thread entry point for cluster_serving_sth_update_thread_.
void ClusterStateController::ClusterServingSTHUpdater() {
  while (true) {
    VLOG(1) << "ClusterServingSTHUpdater going again.";
    unique_lock<mutex> lock(mutex_);
    update_required_cv_.wait(lock, [this]() {
      return update_required_ || exiting_;
    });
    VLOG(1) << "ClusterServingSTHUpdater got ping.";
    if (exiting_) {
      VLOG(1) << "ClusterServingSTHUpdater thread returning.";
      return;
    }
    CHECK(update_required_);
    CHECK_NOTNULL(calculated_serving_sth_.get());
    const SignedTreeHead local_sth(*calculated_serving_sth_);

    update_required_ = false;

    // And then release it before we send the update.
    // This allows any other code to get on with modifying
    // calculated_serving_sth_ in response to cluster state changes
    lock.unlock();

    if (election_->IsMaster()) {
      LOG(INFO) << "Setting cluster serving STH @ " << local_sth.timestamp();
      Status status(store_->SetServingSTH(local_sth));
      LOG_IF(WARNING, !status.ok()) << "SetServingSTH @ "
                                    << local_sth.timestamp()
                                    << " failed: " << status;
    } else {
      LOG(INFO) << "Not setting cluster serving STH because no-longer master.";
    }
  }
}


}  // namespace cert_trans
