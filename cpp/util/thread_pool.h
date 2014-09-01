#ifndef CERT_TRANS_UTIL_THREAD_POOL_H_
#define CERT_TRANS_UTIL_THREAD_POOL_H_

#include <boost/function.hpp>
#include <boost/scoped_ptr.hpp>

#include "base/macros.h"

namespace cert_trans {


// Provides a fixed size thread pool to run closures on. The pool is
// sized according to the number of cores in the system.
class ThreadPool {
 public:
  // Creates the threads.
  ThreadPool();

  // The destructor will wait for any outstanding closures to finish.
  ~ThreadPool();

  // Arranges for "closure" to be called in the thread pool. The
  // function must not be empty.
  void Add(const boost::function<void()> & closure);

 private:
  class Impl;
  const boost::scoped_ptr<Impl> impl_;

  DISALLOW_COPY_AND_ASSIGN(ThreadPool);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_THREAD_POOL_H_
