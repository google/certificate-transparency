#include "fetcher/remote_peer.h"

#include <chrono>
#include <gflags/gflags.h>
#include <glog/logging.h>

#include "base/time_support.h"

using ct::SignedTreeHead;
using std::chrono::seconds;
using std::lock_guard;
using std::make_shared;
using std::move;
using std::mutex;
using std::placeholders::_1;
using std::shared_ptr;
using std::unique_ptr;
using util::TaskHold;

namespace cert_trans {

DEFINE_int32(remote_peer_sth_refresh_interval_seconds, 10,
             "Number of seconds between checks for updated STHs from the "
             "remote peer.");


struct RemotePeer::Impl {
  Impl(unique_ptr<LogVerifier>&& verifier, AsyncLogClient* client,
       const std::function<void(const ct::SignedTreeHead&)>& on_new_sth,
       util::Task* task)
      : verifier_(move(verifier)),
        client_(CHECK_NOTNULL(client)),
        on_new_sth_(on_new_sth),
        task_(CHECK_NOTNULL(task)) {
    CHECK(verifier_);
  }

  const std::unique_ptr<LogVerifier> verifier_;
  AsyncLogClient* const client_;
  const std::function<void(const ct::SignedTreeHead&)> on_new_sth_;
  util::Task* const task_;

  mutex lock_;
  shared_ptr<SignedTreeHead> sth_;

  void FetchSTH(util::Task* task);
  void DoneGetSTH(const std::shared_ptr<ct::SignedTreeHead>& on_new_sth,
                  AsyncLogClient::Status status);
};


void RemotePeer::Impl::FetchSTH(util::Task* task) {
  if (CHECK_NOTNULL(task_)->CancelRequested()) {
    task_->Return(util::Status::CANCELLED);
    return;
  }
  shared_ptr<SignedTreeHead> next_sth(make_shared<SignedTreeHead>());
  client_->GetSTH(next_sth.get(), bind(&Impl::DoneGetSTH, this, next_sth, _1));
}


void RemotePeer::Impl::DoneGetSTH(
    const std::shared_ptr<ct::SignedTreeHead>& new_sth,
    AsyncLogClient::Status status) {
  if (task_->CancelRequested()) {
    task_->Return(util::Status::CANCELLED);
    return;
  }

  // TODO(pphaneuf): At least some of the CHECK-failing here might
  // have to be changed to... something else.
  CHECK_EQ(verifier_->VerifySignedTreeHead(
               *new_sth, 0, (time(NULL) + 10) * kNumMillisPerSecond),
           LogVerifier::VERIFY_OK)
      << "could not validate STH:\n" << new_sth->DebugString();

  // TODO(alcutter): Need to check STH consistency here, including for older
  // STHs which might come in.

  lock_guard<mutex> lock(lock_);

  if (new_sth->tree_size() < 0) {
    LOG(WARNING) << "Unexpected tree size in new_sth:\n"
                 << new_sth->DebugString();
  } else if (sth_ && new_sth->tree_size() < sth_->tree_size()) {
    LOG(WARNING) << "Received old STH:\n" << new_sth->DebugString();
  } else if (!sth_ || new_sth->timestamp() > sth_->timestamp()) {
    // This STH is good, we'll take it.
    sth_ = new_sth;
    if (on_new_sth_) {
      on_new_sth_(*sth_);
    }
  }

  // Schedule another STH fetch
  task_->executor()->Delay(
      seconds(FLAGS_remote_peer_sth_refresh_interval_seconds),
      task_->AddChild(bind(&RemotePeer::Impl::FetchSTH, this, _1)));
}


RemotePeer::RemotePeer(
    unique_ptr<AsyncLogClient>&& client, unique_ptr<LogVerifier>&& verifier,
    const std::function<void(const ct::SignedTreeHead&)>& on_new_sth,
    util::Task* task)
    : Peer(move(client)),
      impl_(new Impl(move(verifier), client_.get(), on_new_sth, task)) {
  TaskHold hold(task);
  task->DeleteWhenDone(impl_);

  impl_->FetchSTH(nullptr);
}


RemotePeer::~RemotePeer() {
  impl_->task_->Return(util::Status::CANCELLED);
}


int64_t RemotePeer::TreeSize() const {
  lock_guard<mutex> lock(impl_->lock_);
  return (impl_->sth_ && impl_->sth_->has_tree_size())
             ? impl_->sth_->tree_size()
             : -1;
}


}  // namespace cert_trans
