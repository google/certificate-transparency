#ifndef CERT_TRANS_UTIL_ETCD_H_
#define CERT_TRANS_UTIL_ETCD_H_

#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include <list>
#include <map>
#include <stdint.h>
#include <string>

#include "base/macros.h"
#include "util/libevent_wrapper.h"

class JsonObject;

namespace cert_trans {


class EtcdClient {
 public:
  class Status {
   public:
    Status() : status_(201), message_("") {
    }
    Status(int status, const std::string& message)
        : status_(status), message_(message) {
    }
    Status(int status, const boost::shared_ptr<JsonObject>& json);

    bool ok() const {
      return status_ == 201;
    }

    int status() const {
      return status_;
    }

    const std::string& message() const {
      return message_;
    }

   private:
    const int status_;
    const std::string message_;
  };

  typedef boost::function<void(Status status, int index,
                               const std::string& value)> GetCallback;
  typedef boost::function<void(
      Status status, const std::list<std::pair<std::string, int> >& values)>
      GetAllCallback;
  typedef boost::function<void(Status status, int index)> CreateCallback;
  typedef boost::function<void(Status status, const std::string& key,
                               int index)> CreateInQueueCallback;
  typedef boost::function<void(Status status, int new_index)> UpdateCallback;
  typedef boost::function<void(Status status)> DeleteCallback;

  // TODO(pphaneuf): This should take a set of servers, not just one.
  EtcdClient(const boost::shared_ptr<libevent::Base>& event_base,
             const std::string& host, uint16_t port);

  virtual ~EtcdClient();

  void Get(const std::string& key, const GetCallback& cb);

  void GetAll(const std::string& dir, const GetAllCallback& cb);

  void Create(const std::string& key, const std::string& value,
              const CreateCallback& cb);

  void CreateInQueue(const std::string& dir, const std::string& value,
                     const CreateInQueueCallback& cb);

  void Update(const std::string& key, const std::string& value,
              const int previous_index, const UpdateCallback& cb);

  void Delete(const std::string& key, const int current_index,
              const DeleteCallback& cb);

 protected:
  typedef boost::function<void(
      Status status, const boost::shared_ptr<JsonObject>&)> GenericCallback;

  EtcdClient();  // Testing only

  virtual void Generic(const std::string& key,
                       const std::map<std::string, std::string>& params,
                       evhttp_cmd_type verb, const GenericCallback& cb);

 private:
  typedef std::map<std::pair<std::string, uint16_t>,
                   boost::shared_ptr<libevent::HttpConnection> > ConnectionMap;

  struct Request;

  // If MaybeUpdateLeader returns true, the handling of the response
  // should be aborted, as a new leader was found, and the request has
  // been retried on the new leader.
  bool MaybeUpdateLeader(libevent::HttpRequest* req, Request* etcd_req);
  void RequestDone(libevent::HttpRequest* req, Request* etcd_req);

  boost::shared_ptr<libevent::HttpConnection> GetConnection(
      const std::string& host, uint16_t port);

  const boost::shared_ptr<libevent::Base> event_base_;

  boost::mutex lock_;
  ConnectionMap conns_;
  // Last known leader.
  boost::shared_ptr<libevent::HttpConnection> leader_;

  DISALLOW_COPY_AND_ASSIGN(EtcdClient);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_ETCD_H_
