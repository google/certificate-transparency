#ifndef CERT_TRANS_UTIL_FAKE_ETCD_H_
#define CERT_TRANS_UTIL_FAKE_ETCD_H_

#include <map>
#include <queue>
#include <string>

#include "util/etcd.h"
#include "util/thread_pool.h"


namespace cert_trans {

class FakeEtcdClient : public EtcdClient {
 public:
  FakeEtcdClient();

  virtual ~FakeEtcdClient() = default;

  void DumpEntries();

  Watcher* CreateWatcher(const std::string& key,
                         const Watcher::WatchCallback& cb) override;

 protected:
  void Generic(const std::string& key,
               const std::map<std::string, std::string>& params,
               evhttp_cmd_type verb, const GenericCallback& cb) override;

 private:
  class FakeWatcher;

  void PurgeExpiredEntries();

  void NotifyForPath(const std::string& path);

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

  void RemoveWatcher(const void* cookie);

  // Schedules a callback to be run.
  // Callbacks should not block.
  void ScheduleCallback(const std::function<void()>& cb);

  std::mutex mutex_;
  int64_t index_;
  std::map<std::string, Node> entries_;
  std::map<std::string, std::vector<std::pair<Watcher::WatchCallback, void*>>>
      watches_;
  ThreadPool pool_;
};


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_FAKE_ETCD_H_
