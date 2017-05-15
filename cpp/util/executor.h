#ifndef CERT_TRANS_UTIL_EXECUTOR_H_
#define CERT_TRANS_UTIL_EXECUTOR_H_

#include <chrono>
#include <functional>

namespace util {
class Task;


class Executor {
 public:
  Executor(const Executor&) = delete;
  Executor& operator=(const Executor&) = delete;
  virtual ~Executor() = default;

  virtual void Add(const std::function<void()>& closure) = 0;
  virtual void Delay(const std::chrono::duration<double>& delay,
                     Task* task) = 0;

 protected:
  Executor() = default;
};


}  // namespace util

#endif  // CERT_TRANS_UTIL_EXECUTOR_H_
