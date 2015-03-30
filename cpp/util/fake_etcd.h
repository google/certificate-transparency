#ifndef CERT_TRANS_UTIL_FAKE_ETCD_H_
#define CERT_TRANS_UTIL_FAKE_ETCD_H_

#include <deque>
#include <map>
#include <queue>
#include <string>

#include "util/etcd.h"
#include "util/task.h"


namespace cert_trans {

class FakeEtcdClient : public EtcdClient {
 public:
  FakeEtcdClient();

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
               UrlFetcher::Verb verb, GenericResponse* resp,
               util::Task* task) override;

 private:
  void PurgeExpiredEntries();

  void NotifyForPath(const std::unique_lock<std::mutex>& lock,
                     const std::string& path);

  void GetSingleEntry(const std::string& key, GenericResponse* resp,
                      util::Task* task);

  void GetDirectory(const std::string& key, GenericResponse* resp,
                    util::Task* task);

  void HandleGet(const std::string& key,
                 const std::map<std::string, std::string>& params,
                 GenericResponse* resp, util::Task* task);

  util::Status CheckCompareFlags(
      const std::map<std::string, std::string> params, const std::string& key);

  void HandlePost(const std::string& key,
                  const std::map<std::string, std::string>& params,
                  GenericResponse* resp, util::Task* task);

  void HandlePut(const std::string& key,
                 const std::map<std::string, std::string>& params,
                 GenericResponse* resp, util::Task* task);

  void HandleDelete(const std::string& key,
                    const std::map<std::string, std::string>& params,
                    GenericResponse* resp, util::Task* task);

  void CancelWatch(util::Task* task);

  // Arranges for the watch callbacks to be called in order. Should be
  // called with mutex_ held.
  void ScheduleWatchCallback(const std::unique_lock<std::mutex>& lock,
                             util::Task* task,
                             const std::function<void()>& callback);
  void RunWatchCallback();

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
