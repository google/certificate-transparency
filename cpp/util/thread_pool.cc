#include "util/thread_pool.h"

#include <condition_variable>
#include <glog/logging.h>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

using std::condition_variable;
using std::function;
using std::lock_guard;
using std::mutex;
using std::queue;
using std::thread;
using std::unique_lock;
using std::vector;

namespace cert_trans {


class ThreadPool::Impl {
 public:
  ~Impl();

  void Worker();

  // TODO(pphaneuf): I'd like this to be const, but it required
  // jumping through a few more hoops, keeping it simple for now.
  vector<thread> threads_;

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
  for (auto& thread : threads_) {
    thread.join();
  }
}


void ThreadPool::Impl::Worker() {
  while (true) {
    function<void()> closure;

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
      if (!queue_.front())
        break;

      closure = queue_.front();
      queue_.pop();
    }

    // Make sure not to hold the lock while calling the closure.
    closure();
  }
}


ThreadPool::ThreadPool()
    : ThreadPool(thread::hardware_concurrency() > 0
                     ? thread::hardware_concurrency()
                     : 1) {
}


ThreadPool::ThreadPool(size_t num_threads) : impl_(new Impl) {
  CHECK_GT(num_threads, 0);
  LOG(INFO) << "ThreadPool starting with " << num_threads << " threads";
  for (int i = 0; i < num_threads; ++i)
    impl_->threads_.emplace_back(thread(&Impl::Worker, impl_.get()));
}


ThreadPool::~ThreadPool() {
  // Need to have this method defined where the definition of
  // ThreadPool::Impl is visible.
}


void ThreadPool::Add(const function<void()>& closure) {
  // Empty closures signal a thread to exit, don't allow that (also,
  // it doesn't make sense).
  if (!closure) {
    return;
  }

  {
    lock_guard<mutex> lock(impl_->queue_lock_);
    impl_->queue_.push(closure);
  }
  impl_->queue_cond_var_.notify_one();
}


}  // namespace cert_trans
