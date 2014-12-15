#ifndef CERT_TRANS_UTIL_FAKE_ETCD_H_
#define CERT_TRANS_UTIL_FAKE_ETCD_H_

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

  void Watch(const std::string& key, const WatchCallback& cb,
             util::Task* task) override;

 protected:
  void Generic(const std::string& key,
               const std::map<std::string, std::string>& params,
               evhttp_cmd_type verb, const GenericCallback& cb) override;

 private:
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

  void CancelWatch(util::Task* task);

  // Schedules a callback to be run.
  // Callbacks should not block.
  void ScheduleCallback(const std::function<void()>& cb);

  const std::shared_ptr<libevent::Base> base_;
  std::mutex mutex_;
  int64_t index_;
  std::map<std::string, Node> entries_;
  std::map<std::string, std::vector<std::pair<WatchCallback, util::Task*>>>
      watches_;

  friend class ElectionTest;
};


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_FAKE_ETCD_H_
