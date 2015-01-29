#include "fetcher/fetcher.h"

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <memory>
#include <mutex>

#include "base/macros.h"

using cert_trans::AsyncLogClient;
using cert_trans::LoggedCertificate;
using cert_trans::Peer;
using std::bind;
using std::lock_guard;
using std::move;
using std::mutex;
using std::placeholders::_1;
using std::unique_ptr;
using std::vector;
using util::Status;
using util::Task;
using util::TaskHold;

DEFINE_int32(fetcher_concurrent_fetches, 100,
             "number of concurrent fetch requests");
DEFINE_int32(fetcher_batch_size, 1000,
             "maximum number of entries to fetch per request");

namespace {


struct Range {
  enum State {
    HAVE,
    FETCHING,
    WANT,
  };

  Range(State state, int64_t size, unique_ptr<Range>&& next = nullptr)
      : state_(state), size_(size), next_(move(next)) {
    CHECK(state_ == HAVE || state_ == FETCHING || state_ == WANT);
    CHECK_GT(size_, 0);
  };

  mutex lock_;
  State state_;
  int64_t size_;
  unique_ptr<Range> next_;
};


struct FetchState {
  FetchState(Database<LoggedCertificate>* db, Peer* peer, Task* task);

  void WalkEntries();
  void FetchRange(Range* current, int64_t index, Task* child_task);
  void GetEntriesDone(int64_t index, Range* range,
                      const vector<AsyncLogClient::Entry>* retval,
                      AsyncLogClient::Status status, Task* child_task);
  void WriteToDatabase(int64_t index, Range* range,
                       const vector<AsyncLogClient::Entry>* retval,
                       AsyncLogClient::Status fetch_status, Task* child_task);

  Database<LoggedCertificate>* const db_;
  Peer* const peer_;
  Task* const task_;

  mutex lock_;
  int64_t start_;
  unique_ptr<Range> entries_;

 private:
  DISALLOW_COPY_AND_ASSIGN(FetchState);
};


FetchState::FetchState(Database<LoggedCertificate>* db, Peer* peer, Task* task)
    : db_(CHECK_NOTNULL(db)),
      peer_(CHECK_NOTNULL(peer)),
      task_(CHECK_NOTNULL(task)) {
  const int64_t local_tree_size(db_->TreeSize());

  const int64_t remote_tree_size(peer->TreeSize());
  CHECK_GE(local_tree_size, 0);

  // Nothing to do...
  if (remote_tree_size <= local_tree_size) {
    task_->Return();
    return;
  }

  start_ = local_tree_size;
  entries_.reset(new Range(Range::WANT, remote_tree_size - local_tree_size));

  WalkEntries();
}


void FetchState::WalkEntries() {
  lock_guard<mutex> lock(lock_);

  // Prune fetched sequences at the beginning.
  while (entries_ && entries_->state_ == Range::HAVE) {
    VLOG(1) << "pruning " << entries_->size_ << " at offset " << start_;
    start_ += entries_->size_;
    entries_ = move(entries_->next_);
  }

  // Are we done?
  if (!entries_) {
    task_->Return();
    return;
  }

  int64_t index(start_);
  int num_fetch(0);
  for (Range* current = entries_.get(); current;
       index += current->size_, current = current->next_.get()) {
    lock_guard<mutex> lock(current->lock_);

    // Coalesce with the next Range, if possible.
    if (current->state_ != Range::FETCHING) {
      while (current->next_ && current->next_->state_ == current->state_) {
        current->size_ += current->next_->size_;
        current->next_ = move(current->next_->next_);
      }
    }

    switch (current->state_) {
      case Range::HAVE:
        VLOG(2) << "at offset " << index << ", we have " << current->size_
                << " entries";
        break;

      case Range::FETCHING:
        VLOG(2) << "at offset " << index << ", fetching " << current->size_
                << " entries";
        ++num_fetch;
        break;

      case Range::WANT:
        VLOG(2) << "at offset " << index << ", we want " << current->size_
                << " entries";

        // If the range is bigger than the maximum batch size, split it.
        if (current->size_ > FLAGS_fetcher_batch_size) {
          current->next_.reset(
              new Range(Range::WANT, current->size_ - FLAGS_fetcher_batch_size,
                        move(current->next_)));
          current->size_ = FLAGS_fetcher_batch_size;
        }

        FetchRange(current, index,
                   task_->AddChild(bind(&FetchState::WalkEntries, this)));
        ++num_fetch;

        break;
    }

    if (num_fetch >= FLAGS_fetcher_concurrent_fetches) {
      break;
    }
  }
}


void FetchState::FetchRange(Range* current, int64_t index, Task* child_task) {
  const int64_t end_index(index + current->size_ - 1);
  VLOG(1) << "fetching from offset " << index << " to " << end_index;

  vector<AsyncLogClient::Entry>* const retval(
      new vector<AsyncLogClient::Entry>);
  child_task->DeleteWhenDone(retval);

  peer_->client().GetEntries(index, end_index, retval,
                             bind(&FetchState::GetEntriesDone, this, index,
                                  current, retval, _1, child_task));

  current->state_ = Range::FETCHING;
}


void FetchState::GetEntriesDone(int64_t index, Range* range,
                                const vector<AsyncLogClient::Entry>* retval,
                                AsyncLogClient::Status status,
                                Task* child_task) {
  // Writing to the database is a blocking operation, but we are
  // currently on some "unknown" thread (and realistically, probably
  // the libevent thread, which should not block!), so move us back to
  // a known thread where blocking is allowed.
  task_->executor()->Add(bind(&FetchState::WriteToDatabase, this, index, range,
                              retval, status, child_task));
}


void FetchState::WriteToDatabase(int64_t index, Range* range,
                                 const vector<AsyncLogClient::Entry>* retval,
                                 AsyncLogClient::Status fetch_status,
                                 Task* child_task) {
  CHECK_GT(retval->size(), 0);

  if (fetch_status != AsyncLogClient::OK) {
    LOG(INFO) << "error fetching entries at index " << index << ": "
              << fetch_status;
    lock_guard<mutex> lock(range->lock_);
    range->state_ = Range::WANT;
    // TODO(pphaneuf): If AsyncLogClient used util::Status, we'd just
    // pass that back here.
    child_task->Return(Status(util::error::UNKNOWN, "AsyncLogClient error"));
    return;
  }

  VLOG(1) << "received " << retval->size() << " entries at offset " << index;
  int64_t processed(0);
  for (const auto& entry : *retval) {
    LoggedCertificate cert;
    if (!cert.CopyFromClientLogEntry(entry)) {
      LOG(WARNING) << "could not convert entry to a LoggedCertificate";
      break;
    }
    cert.set_sequence_number(index++);
    if (db_->CreateSequencedEntry(cert) == Database<LoggedCertificate>::OK) {
      ++processed;
    } else {
      LOG(WARNING) << "could not insert entry into the database:\n"
                   << cert.DebugString();
      break;
    }
  }

  {
    lock_guard<mutex> lock(range->lock_);
    // TODO(pphaneuf): If we have problems fetching entries, to what
    // point should we retry? Or should we just return on the task
    // with an error?
    if (processed > 0) {
      // If we don't receive everything, split up the range.
      if (range->size_ > processed) {
        range->next_.reset(new Range(Range::WANT, range->size_ - processed,
                                     move(range->next_)));
        range->size_ = processed;
      }

      range->state_ = Range::HAVE;
    } else {
      range->state_ = Range::WANT;
    }
  }

  Status status;
  if (processed < retval->size()) {
    status = Status(util::error::INTERNAL,
                    "could not write some entries to the database");
  }

  child_task->Return(status);
}


}  // namespace

namespace cert_trans {


void FetchLogEntries(Database<LoggedCertificate>* db, Peer* peer, Task* task) {
  TaskHold hold(task);
  task->DeleteWhenDone(new FetchState(db, peer, task));
}


}  // namespace cert_trans
