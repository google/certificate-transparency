#include "util/masterelection.h"

#include <climits>
#include <functional>
#include <gflags/gflags.h>
#include <glog/logging.h>

#include "util/periodic_closure.h"

namespace cert_trans {

using std::bind;
using std::chrono::seconds;
using std::mutex;
using std::placeholders::_1;
using std::placeholders::_2;
using std::shared_ptr;
using std::string;
using std::unique_lock;
using std::vector;

DEFINE_int32(master_keepalive_interval_seconds, 60,
             "Interval between refreshing mastership proposal.");


namespace {


// Special backing string which indicates that we're not backing any proposal.
const char kNoBacking[] = "";


// Returns |s| with a '/' appended if the last char is not already a '/'
string EnsureEndsWithSlash(const string& s) {
  if (s.empty() || s.back() != '/') {
    return s + '/';
  } else {
    return s;
  }
}


}  // namespace


MasterElection::MasterElection(const shared_ptr<libevent::Base>& base,
                               EtcdClient* client, const string& proposal_dir,
                               const string& node_id)
    : base_(base),
      client_(CHECK_NOTNULL(client)),
      proposal_dir_(EnsureEndsWithSlash(proposal_dir)),
      my_proposal_path_(proposal_dir_ + node_id),
      proposal_state_(ProposalState::NONE),
      running_(false),
      backed_proposal_(kNoBacking),
      is_master_(false) {
  CHECK_NE(kNoBacking, node_id);
}


MasterElection::~MasterElection() {
  VLOG(1) << my_proposal_path_ << ": Joining election";
  CHECK(proposal_state_ == ProposalState::NONE);
  VLOG(1) << "~" << my_proposal_path_;
}


void MasterElection::StartElection() {
  VLOG(1) << my_proposal_path_ << ": Joining election";
  {
    unique_lock<mutex> lock(mutex_);
    CHECK(!running_);
    running_ = true;

    Transition(lock, ProposalState::AWAITING_CREATION);
  }
  base_->Add(bind(&MasterElection::CreateProposal, this));
}


void MasterElection::StopElection() {
  VLOG(1) << my_proposal_path_ << ": Departing election.";

  // Stop the updates from the watch. Do this before taking the lock,
  // because the watch callback takes that lock. This means that we'll
  // stop updating our proposal, and maybe delay a master election,
  // but that's okay, as we're about to delete our proposal
  // altogether.
  VLOG(1) << my_proposal_path_ << ": Cancelling watch...";
  proposal_watch_->Cancel();
  proposal_watch_->Wait();
  proposal_watch_.reset();

  unique_lock<mutex> lock(mutex_);
  CHECK(running_);
  running_ = false;
  is_master_ = false;
  is_master_cv_.notify_all();

  // But wait for any in-flight updates to finish
  VLOG(1) << my_proposal_path_ << ": waiting for in-flight proposal update "
          << "to complete.";
  proposal_state_cv_.wait(lock, [this]() {
    return proposal_state_ == ProposalState::UP_TO_DATE;
  });

  // No more refresh callbacks (this is not synchronous, the refresh
  // callback might be running right now, trying to lock the mutex, so
  // the callback has to be able to handle itself after we've
  // stopped):
  proposal_refresh_callback_.reset();

  // Delete our proposal so we can't accidentally become master after we've
  // left:
  Transition(lock, ProposalState::AWAITING_DELETE);
  base_->Add(bind(&MasterElection::DeleteProposal, this));
  // Wait for the proposal to actually be deleted before we return.
  VLOG(1) << my_proposal_path_ << ": Waiting for delete to complete.";
  proposal_state_cv_.wait(lock, [this]() {
    return proposal_state_ == ProposalState::NONE;
  });
  VLOG(1) << my_proposal_path_ << ": Departed election.";
}


bool MasterElection::WaitToBecomeMaster() const {
  VLOG(1) << my_proposal_path_ << ": Waiting to become master";
  unique_lock<mutex> lock(mutex_);
  // We'll unblock if either we're master, or someone stopped the election.
  is_master_cv_.wait(lock,
                     [this, &lock]() { return IsMaster(lock) || !running_; });
  return IsMaster(lock);
}


bool MasterElection::IsMaster() const {
  unique_lock<mutex> lock(mutex_);
  return IsMaster(lock);
}


bool MasterElection::IsMaster(const unique_lock<mutex>& lock) const {
  CHECK(lock.owns_lock());
  return is_master_;
}


void MasterElection::Transition(const unique_lock<mutex>& lock,
                                const ProposalState to) {
  CHECK(lock.owns_lock());
  VLOG(1) << my_proposal_path_ << ": Transition "
          << static_cast<int>(proposal_state_) << " -> "
          << static_cast<int>(to);
  switch (proposal_state_) {
    case ProposalState::NONE:
      CHECK(to == ProposalState::AWAITING_CREATION);
      break;
    case ProposalState::AWAITING_CREATION:
      CHECK(to == ProposalState::CREATING);
      break;
    case ProposalState::CREATING:
      CHECK(to == ProposalState::UP_TO_DATE);
      break;
    case ProposalState::UP_TO_DATE:
      CHECK(to == ProposalState::AWAITING_UPDATE ||
            to == ProposalState::AWAITING_DELETE)
          << "proposal_state_: " << static_cast<int>(proposal_state_)
          << " to: " << static_cast<int>(to);
      break;
    case ProposalState::AWAITING_UPDATE:
      CHECK(to == ProposalState::UPDATING);
      break;
    case ProposalState::UPDATING:
      CHECK(to == ProposalState::UP_TO_DATE);
      break;
    case ProposalState::AWAITING_DELETE:
      CHECK(to == ProposalState::DELETING);
      break;
    case ProposalState::DELETING:
      CHECK(to == ProposalState::NONE);
      break;
    default:
      CHECK(false) << "Unknown state: " << static_cast<int>(proposal_state_);
  }
  proposal_state_ = to;
  proposal_state_cv_.notify_all();
}


void MasterElection::CreateProposal() {
  unique_lock<mutex> lock(mutex_);
  Transition(lock, ProposalState::CREATING);

  // We'll create an empty file indicating we're not backing anyone, so as to
  // avoid disrupting an existing settled election.
  // Technically this could already exist if we had mastership before, crashed,
  // and then restarted before the TTL expired.
  client_->CreateWithTTL(my_proposal_path_, kNoBacking,
                         seconds(FLAGS_master_keepalive_interval_seconds * 2),
                         bind(&MasterElection::ProposalCreateDone, this, _1,
                              _2));
}


void MasterElection::ProposalCreateDone(util::Status status, int64_t index) {
  unique_lock<mutex> lock(mutex_);
  // TODO(alcutter): recover gracefully if we're restarting and found an old
  // proposal from this node
  CHECK(status.ok()) << my_proposal_path_
                     << ": Problem creating proposal: " << status;
  Transition(lock, ProposalState::UP_TO_DATE);

  VLOG(1) << my_proposal_path_ << ": Mastership proposal created at index "
          << index;

  my_proposal_modified_index_ = my_proposal_create_index_ = index;
  // Start a periodic callback to keep our proposal from being garbage
  // collected
  CHECK(!proposal_refresh_callback_);
  VLOG(1) << my_proposal_path_ << ": Creating refresh Callback";
  proposal_refresh_callback_.reset(new PeriodicClosure(
      base_, seconds(FLAGS_master_keepalive_interval_seconds),
      bind(&MasterElection::ProposalKeepAliveCallback, this)));

  // Watch the proposal directory so we're aware of other proposals
  // coming and going
  VLOG(1) << my_proposal_path_ << ": Watching proposals";
  CHECK(!proposal_watch_);
  proposal_watch_.reset(new util::SyncTask(base_.get()));
  client_->Watch(proposal_dir_,
                 bind(&MasterElection::OnProposalUpdate, this, _1),
                 proposal_watch_->task());
  VLOG(1) << my_proposal_path_ << ": Joined election";
}


bool MasterElection::MaybeUpdateProposal(const unique_lock<mutex>& lock,
                                         const string& backed) {
  CHECK(lock.owns_lock());
  if (proposal_state_ == ProposalState::UPDATING ||
      proposal_state_ == ProposalState::AWAITING_UPDATE) {
    // Don't want to have more than one proposal update happening at
    // the same time so we'll just bail this one.  It's ok, though,
    // because the currently in-flight update will cause a call to
    // ProposalUpdate() via the watch which should prompt another
    // update attempt if it turns out to still be necessary.
    VLOG(1) << my_proposal_path_ << ": Dropping proposal update backing "
            << backed << " because already have a proposal update in "
            << "flight.";
    return false;
  }
  Transition(lock, ProposalState::AWAITING_UPDATE);
  base_->Add(bind(&MasterElection::UpdateProposal, this, backed));
  return true;
}


void MasterElection::UpdateProposal(const string& backed) {
  unique_lock<mutex> lock(mutex_);
  Transition(lock, ProposalState::UPDATING);

  VLOG(1) << my_proposal_path_ << ": Updating proposal backing " << backed;

  // TODO(alcutter): Set the HTTP timeout inside here to something sensible.
  client_->UpdateWithTTL(my_proposal_path_, backed,
                         seconds(FLAGS_master_keepalive_interval_seconds * 2),
                         my_proposal_modified_index_,
                         bind(&MasterElection::ProposalUpdateDone, this, _1,
                              backed, _2));
}


void MasterElection::ProposalUpdateDone(util::Status status,
                                        const string& backed,
                                        int64_t new_index) {
  unique_lock<mutex> lock(mutex_);
  // TODO(alcutter): Handle this
  CHECK(status.ok()) << my_proposal_path_ << ": " << status;
  Transition(lock, ProposalState::UP_TO_DATE);

  // Keep a note of the current modification index of our proposal since
  // we'll need it in order to update or delete the proposal
  my_proposal_modified_index_ = new_index;
  VLOG(1) << my_proposal_path_ << ": Proposal refreshed @ " << new_index;
}


void MasterElection::DeleteProposal() {
  unique_lock<mutex> lock(mutex_);
  Transition(lock, ProposalState::DELETING);

  VLOG(1) << my_proposal_path_ << ": Deleting proposal";
  client_->Delete(my_proposal_path_, my_proposal_modified_index_,
                  bind(&MasterElection::ProposalDeleteDone, this, _1));
}


void MasterElection::ProposalDeleteDone(util::Status status) {
  unique_lock<mutex> lock(mutex_);
  if (!status.ok()) {
    LOG(WARNING) << status;
  }

  VLOG(1) << my_proposal_path_ << ": Delete done.";

  // Now clean up
  my_proposal_create_index_ = -1;
  proposals_.clear();
  Transition(lock, ProposalState::NONE);
}


void MasterElection::ProposalKeepAliveCallback() {
  unique_lock<mutex> lock(mutex_);
  VLOG(1) << my_proposal_path_ << ": Proposal Keep-Alive fired.";
  if (!running_) {
    VLOG(1) << my_proposal_path_
            << ": But we're not running so bailing on updates.";
    return;
  }

  MaybeUpdateProposal(lock, backed_proposal_);
}


void MasterElection::UpdateProposalView(
    const vector<EtcdClient::WatchUpdate>& updates) {
  for (const auto& update : updates) {
    if (update.exists_) {
      VLOG(1) << my_proposal_path_
              << ": Proposal updated: " << update.node_.ToString();
      proposals_[update.node_.key_] = update.node_;
    } else {
      VLOG(1) << my_proposal_path_
              << ": Proposal deleted: " << update.node_.ToString();
      CHECK_EQ(1, proposals_.erase(update.node_.key_))
          << my_proposal_path_
          << ": Unknown proposal deleted: " << update.node_.ToString();
    }
  }
}


bool MasterElection::DetermineApparentMaster(
    EtcdClient::Node* apparent_master) const {
  EtcdClient::Node tmp_master(INT_MAX, INT_MAX, "", "");
  bool found(false);
  for (const auto& pair : proposals_) {
    CHECK_EQ(pair.first, pair.second.key_);
    if (pair.second.created_index_ < tmp_master.created_index_) {
      found = true;
      tmp_master = pair.second;
    }
  }
  if (found) {
    *apparent_master = tmp_master;
  }
  return found;
}


void MasterElection::OnProposalUpdate(
    const vector<EtcdClient::WatchUpdate>& updates) {
  unique_lock<mutex> lock(mutex_);
  CHECK_GE(updates.size(), 1);
  VLOG(1) << my_proposal_path_ << ": Got " << updates.size() << " update(s)";
  if (!running_) {
    VLOG(1) << my_proposal_path_
            << ": But we're not running so bailing on updates.";
    return;
  }

  // First, update our view of the proposals:
  UpdateProposalView(updates);

  // Now figure out who we think the master should be based on proposal
  // creation indicies:
  EtcdClient::Node apparent_master;
  if (!DetermineApparentMaster(&apparent_master)) {
    // Doesn't look like there are any proposals, so nothing to do.
    // Probably shouldn't really happen, but it could be that our proposal got
    // cleaned up because we failed to refresh it before the TTL expired.
    VLOG(1) << my_proposal_path_
            << ": No proposals to consider; no master currently";
    // Since nobody is a master, that includes us:
    is_master_ = false;
    return;
  }

  // Do we have to update our public statement about who we're backing?
  if (backed_proposal_ != apparent_master.key_) {
    // Yep, looks like the situation has changed
    VLOG(1) << my_proposal_path_ << ": Backed proposal (" << backed_proposal_
            << ") != apparent_master (" << apparent_master.key_ << "), "
            << is_master_;
    // Try to update our proposal to show our support of the apparent master.
    // If this fails it'll be because there's already an update in-flight, so
    // we'll get notified of that shortly and end up here agin, at which point
    // we can try again.
    if (MaybeUpdateProposal(lock, apparent_master.key_)) {
      // We managed to send the the update so store our backing here so we
      // don't continually fire off 'updates' saying the same thing
      backed_proposal_ = apparent_master.key_;
    }
    // Since we changed our mind about who to back, that means there's not
    // currently consensus, so we can't be a master either.
    // Strictly this might not be true - if everyone else already voted for us
    // we could short circuit and set this true here, but there's no really
    // anything to be gained from that other than more complex code.
    is_master_ = false;
    return;
  }

  // Check to see whether the apparent master from the previous stage is backed
  // by all participating nodes:
  bool found_master(!proposals_.empty());
  // Check if everyone is in agreement about who the master is:
  for (const auto& pair : proposals_) {
    // Discount any participant who has explicitly abstained from the vote.
    // This is because participants who have just joined the election will not
    // have had a chance to decide who to back, this would cause temporary
    // blibs to No Master for the election each time a new participant joined,
    // so we allow them to abstain from the vote, they should then analyze the
    // situation and update their proposal with new backing info, at which
    // point everybody will run OnProposalUpdate() and check for
    // consensus again.
    if (pair.second.value_ == kNoBacking) {
      continue;
    }
    if (pair.second.value_ != apparent_master.key_) {
      // Whoops, we don't have agreement: nobody is a master at the moment.
      // In effect, we're now waiting for everybody to update their proposals
      // an reach agreement for who the master is, or, possibly, for the
      // dissenting participants (who have probably just crashed/wedged) to
      // have their proposals expired by etcd.
      VLOG(1) << my_proposal_path_ << ": No master currently, " << is_master_;
      VLOG(1) << my_proposal_path_ << ": Apparent master is "
              << apparent_master.key_ << " but " << pair.first
              << " is backing: " << pair.second.value_;
      found_master = false;
      // No master, so we can't be master
      is_master_ = false;
      return;
    }
  }

  // There must be consensus about who the master is now.
  CHECK(found_master);
  VLOG(2) << my_proposal_path_ << ": Agreed that master is "
          << apparent_master.key_;
  current_master_ = apparent_master;

  // Finally, determine if we're the master, and wake up anyone blocked in
  // WaitToBecomeMaster() if so:
  is_master_ = running_ &&
               (apparent_master.key_ == my_proposal_path_ &&
                apparent_master.created_index_ == my_proposal_create_index_);
  if (is_master_) {
    LOG(INFO) << my_proposal_path_ << ": Became master";
    is_master_cv_.notify_all();
  }
}


}  // namespace cert_trans
