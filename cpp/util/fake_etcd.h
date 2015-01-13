#ifndef CERT_TRANS_UTIL_FAKE_ETCD_H_
#define CERT_TRANS_UTIL_FAKE_ETCD_H_

#include <deque>
#include <map>
#include <queue>
#include <string>

#include "util/etcd.h"
#include "util/task.h"
#include "util/thread_pool.h"


namespace cert_trans {

class FakeEtcdClient : public EtcdClient {
 public:
  FakeEtcdClient(const std::shared_ptr<libevent::Base>& base);

  virtual ~FakeEtcdClient() = default;

  void DumpEntries();

  // The callbacks for *all* watches will be called one at a time, in
  // order, which is a stronger guarantee than the one
  // EtcdClient::Watch has.
  void Watch(const std::string& key, const WatchCallback& cb,
             util::Task* task) override;

 protected:
  void Generic(const std::string& key,
               const std::map<std::string, std::string>& params,
               evhttp_cmd_type verb, const GenericCallback& cb) override;

 private:
  void PurgeExpiredEntries();

  void NotifyForPath(const std::unique_lock<std::mutex>& lock,
                     const std::string& path);

  void GetSingleEntry(const std::string& key, const GenericCallback& cb);

  void GetDirectory(const std::string& key, const GenericCallback& cb);

  void HandleGet(const std::string& key,
                 const std::map<std::string, std::string>& params,
                 const GenericCallback& cb);

  util::Status CheckCompareFlags(
      const std::map<std::string, std::string> params, const std::string& key);

  void HandlePost(const std::string& key,
                  const std::map<std::string, std::string>& params,
                  const GenericCallback& cb);

  void HandlePut(const std::string& key,
                 const std::map<std::string, std::string>& params,
                 const GenericCallback& cb);

  void HandleDelete(const std::string& key,
                    const std::map<std::string, std::string>& params,
                    const GenericCallback& cb);

  void CancelWatch(util::Task* task);

  // Schedules a callback to be run.
  // Callbacks should not block.
  void ScheduleCallback(const std::function<void()>& cb);

  // Arranges for the watch callbacks to be called in order. Should be
  // called with mutex_ held.
  void ScheduleWatchCallback(const std::unique_lock<std::mutex>& lock,
                             util::Task* task,
                             const std::function<void()>& callback);
  void RunWatchCallback();

  const std::shared_ptr<libevent::Base> base_;
  std::mutex mutex_;
  int64_t index_;
  std::map<std::string, Node> entries_;
  std::map<std::string, std::vector<std::pair<WatchCallback, util::Task*>>>
      watches_;
  std::deque<std::pair<util::Task*, std::function<void()>>> watches_callbacks_;

  friend class ElectionTest;
};


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_FAKE_ETCD_H_
