#include "util/thread_pool.h"

#include <boost/thread.hpp>
#include <glog/logging.h>
#include <queue>
#include <vector>

using boost::condition_variable;
using boost::function;
using boost::lock_guard;
using boost::mutex;
using boost::thread;
using boost::unique_lock;
using std::queue;
using std::vector;

namespace cert_trans {


class ThreadPool::Impl {
 public:
  ~Impl();

  void Worker();

  // TODO(pphaneuf): Would have used vector<thread>, but this requires
  // emplace_back, which is not available to us yet (C++11). I'd also
  // like it to be const, but it required to jump a few more hoops,
  // keeping it simple for now.
  vector<thread*> threads_;

  mutex queue_lock_;
  condition_variable queue_cond_var_;
  queue<function<void()> > queue_;
};


ThreadPool::Impl::~Impl() {
  // Start by sending an empty closure to every thread (and notify
  // them), to have them exit cleanly.
  {
    lock_guard<mutex> lock(queue_lock_);
    for (int i = threads_.size(); i > 0; --i)
      queue_.push(function<void()>());
  }
  // Notify all the threads *after* adding all the empty closures, to
  // avoid any races.
  queue_cond_var_.notify_all();

  // Wait for the threads to exit.
  for (vector<thread*>::const_iterator it = threads_.begin();
       it != threads_.end(); ++it) {
    (*it)->join();
    delete *it;
  }
}


void ThreadPool::Impl::Worker() {
  function<void()> closure;
  while (true) {
    closure.clear();

    {
      unique_lock<mutex> lock(queue_lock_);

      // If there's nothing to do, wait until there is.
      if (queue_.empty()) {
        queue_cond_var_.wait(lock);

        // condition_variable::wait can return spuriously.
        if (queue_.empty())
          continue;
      }

      // If we received an empty closure, exit cleanly.
      if (queue_.front().empty())
        break;

      closure = queue_.front();
      queue_.pop();
    }

    // Make sure not to hold the lock while calling the closure.
    closure();
  }
}


ThreadPool::ThreadPool() : impl_(new Impl) {
  const int num_threads(
      thread::hardware_concurrency() > 0 ? thread::hardware_concurrency() : 1);

  LOG(INFO) << "ThreadPool starting with " << num_threads << " threads";
  for (int i = 0; i < num_threads; ++i)
    impl_->threads_.push_back(new thread(&Impl::Worker, impl_.get()));
}


ThreadPool::~ThreadPool() {
  // Need to have this method defined where the definition of
  // ThreadPool::Impl is visible.
}


void ThreadPool::Add(const function<void()>& closure) {
  // Empty closures signal a thread to exit, don't allow that (also,
  // it doesn't make sense).
  CHECK(!closure.empty());

  {
    lock_guard<mutex> lock(impl_->queue_lock_);
    impl_->queue_.push(closure);
  }
  impl_->queue_cond_var_.notify_one();
}


}  // namespace cert_trans
