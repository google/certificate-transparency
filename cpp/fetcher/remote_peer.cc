#include "fetcher/remote_peer.h"

#include <glog/logging.h>

#include "base/time_support.h"

using ct::SignedTreeHead;
using std::lock_guard;
using std::make_shared;
using std::move;
using std::mutex;
using std::placeholders::_1;
using std::shared_ptr;
using std::unique_ptr;
using util::TaskHold;

namespace cert_trans {


struct RemotePeer::Impl {
  Impl(unique_ptr<LogVerifier>&& verifier, util::Task* task)
      : verifier_(move(verifier)), task_(CHECK_NOTNULL(task)) {
    CHECK(verifier_);
  }

  const std::unique_ptr<LogVerifier> verifier_;
  util::Task* const task_;

  mutex lock_;
  shared_ptr<SignedTreeHead> sth_;

  void DoneGetSTH(const std::shared_ptr<ct::SignedTreeHead>& new_sth,
                  AsyncLogClient::Status status);
};


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

  lock_guard<mutex> lock(lock_);

  if (sth_) {
    CHECK_GE(new_sth->tree_size(), sth_->tree_size());
  } else {
    CHECK_GE(new_sth->tree_size(), 0);
  }

  sth_ = new_sth;
}


RemotePeer::RemotePeer(unique_ptr<AsyncLogClient>&& client,
                       unique_ptr<LogVerifier>&& verifier, util::Task* task)
    : Peer(move(client)), impl_(new Impl(move(verifier), task)) {
  TaskHold hold(task);
  task->DeleteWhenDone(impl_);

  shared_ptr<SignedTreeHead> new_sth(make_shared<SignedTreeHead>());
  client_->GetSTH(new_sth.get(), bind(&Impl::DoneGetSTH, impl_, new_sth, _1));
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
