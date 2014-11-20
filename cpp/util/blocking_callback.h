#ifndef CERT_TRANS_UTIL_BLOCKING_CALLBACK_H_
#define CERT_TRANS_UTIL_BLOCKING_CALLBACK_H_

#include <condition_variable>
#include <functional>
#include <mutex>

namespace cert_trans {

class BlockingCallback {
 public:
  BlockingCallback()
      : notify_cb_(std::bind(&BlockingCallback::Notify, this)),
        called_(false) {
  }

  const std::function<void(void)>& Callback() {
    return notify_cb_;
  }


  void Wait() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this]() { return called_; });
  }


 private:
  void Notify() {
    std::unique_lock<std::mutex>(mutex_);
    called_ = true;
    cv_.notify_all();
  }

  const std::function<void(void)> notify_cb_;
  std::mutex mutex_;
  bool called_;
  std::condition_variable cv_;
};


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_BLOCKING_CALLBACK_H_
