#ifndef CERT_TRANS_UTIL_ETCD_H_
#define CERT_TRANS_UTIL_ETCD_H_

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <stdint.h>
#include <string>
#include <vector>

#include "base/macros.h"
#include "util/libevent_wrapper.h"
#include "util/status.h"

class JsonObject;

namespace cert_trans {


class EtcdClient {
 private:
  struct Request;

 public:
  class Watcher {
   public:
    typedef std::function<void(int index, const std::string& value)>
        WatchCallback;

    explicit Watcher(EtcdClient* client, const std::string& key,
                     const WatchCallback& cb);
    ~Watcher();

   private:
    class Impl;

    // The use of shared_ptr here is not a mistake. This doesn't only
    // serve to hide the implementation, but also to have a slightly
    // longer lifetime than the Watcher object itself, to handle
    // requests that are still in-flight after the Watcher is
    // destroyed.
    const std::shared_ptr<Impl> pimpl_;

    DISALLOW_COPY_AND_ASSIGN(Watcher);
  };

  typedef std::function<void(util::Status status, int index,
                             const std::string& value)> GetCallback;
  typedef std::function<void(
      util::Status status,
      const std::vector<std::pair<std::string, int> >& values)> GetAllCallback;
  typedef std::function<void(util::Status status, int index)> CreateCallback;
  typedef std::function<void(util::Status status, const std::string& key,
                             int index)> CreateInQueueCallback;
  typedef std::function<void(util::Status status, int new_index)>
      UpdateCallback;
  typedef std::function<void(util::Status status, int new_index)>
      ForceSetCallback;
  typedef std::function<void(util::Status status)> DeleteCallback;

  // TODO(pphaneuf): This should take a set of servers, not just one.
  EtcdClient(const std::shared_ptr<libevent::Base>& event_base,
             const std::string& host, uint16_t port);

  virtual ~EtcdClient();

  void Get(const std::string& key, const GetCallback& cb);

  void GetAll(const std::string& dir, const GetAllCallback& cb);

  void Create(const std::string& key, const std::string& value,
              const CreateCallback& cb);

  void CreateWithTTL(const std::string& key, const std::string& value,
                     const std::chrono::duration<int>& ttl,
                     const CreateCallback& cb);

  void CreateInQueue(const std::string& dir, const std::string& value,
                     const CreateInQueueCallback& cb);

  void Update(const std::string& key, const std::string& value,
              const int previous_index, const UpdateCallback& cb);

  void UpdateWithTTL(const std::string& key, const std::string& value,
                     const std::chrono::duration<int>& ttl,
                     const int previous_index, const UpdateCallback& cb);

  void ForceSet(const std::string& key, const std::string& value,
                const ForceSetCallback& cb);

  void ForceSetWithTTL(const std::string& key, const std::string& value,
                       const std::chrono::duration<int>& ttl,
                       const ForceSetCallback& cb);

  void Delete(const std::string& key, const int current_index,
              const DeleteCallback& cb);

 protected:
  typedef std::function<void(util::Status status,
                             const std::shared_ptr<JsonObject>&)>
      GenericCallback;

  EtcdClient() = default;  // Testing only

  virtual void Generic(const std::string& key,
                       const std::map<std::string, std::string>& params,
                       evhttp_cmd_type verb, const GenericCallback& cb);

 private:
  typedef std::map<std::pair<std::string, uint16_t>,
                   std::shared_ptr<libevent::HttpConnection> > ConnectionMap;

  // If MaybeUpdateLeader returns true, the handling of the response
  // should be aborted, as a new leader was found, and the request has
  // been retried on the new leader.
  bool MaybeUpdateLeader(const libevent::HttpRequest& req, Request* etcd_req);
  void RequestDone(const std::shared_ptr<libevent::HttpRequest>& req,
                   Request* etcd_req);

  std::shared_ptr<libevent::HttpConnection> GetConnection(
      const std::string& host, uint16_t port);

  std::shared_ptr<libevent::HttpConnection> GetLeader() const;
  std::shared_ptr<libevent::HttpConnection> UpdateLeader(
      const std::string& host, uint16_t port);

  const std::shared_ptr<libevent::Base> event_base_;

  mutable std::mutex lock_;
  ConnectionMap conns_;
  // Last known leader.
  std::shared_ptr<libevent::HttpConnection> leader_;

  DISALLOW_COPY_AND_ASSIGN(EtcdClient);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_ETCD_H_
