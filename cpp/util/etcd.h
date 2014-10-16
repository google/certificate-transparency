#ifndef CERT_TRANS_UTIL_ETCD_H_
#define CERT_TRANS_UTIL_ETCD_H_

#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include <map>
#include <stdint.h>
#include <string>

#include "base/macros.h"
#include "util/json_wrapper.h"
#include "util/libevent_wrapper.h"

namespace cert_trans {

class EtcdClient {
 public:
  class Status {
   public:
    Status() : status_(201), message_("") {}

    Status(int status, const std::string& message)
        : status_(status), message_(message) {}

    Status(int status, const boost::shared_ptr<JsonObject>& json)
        : status_(status), message_("") {
      if (status_ != 201) {
        const JsonString m(*json, "message");
        if (!m.Ok()) {
          message_ = json->DebugString();
        } else {
          message_ = m.Value();
        }
      }
    }

    bool ok() const { return status_ == 201; }

    int status() const { return status_; }

    const std::string& message() const { return message_; }

   private:
    int status_;
    std::string message_;
  };

  typedef boost::function<void(
      Status status, const boost::shared_ptr<JsonObject>&)> GenericCallback;

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

  virtual void Get(const std::string& key, const GetCallback& cb);

  virtual void GetAll(const std::string& dir, const GetAllCallback& cb);

  virtual void Create(const std::string& key, const std::string& value,
                      const CreateCallback& cb);

  virtual void CreateInQueue(const std::string& dir, const std::string& value,
                             const CreateInQueueCallback& cb);

  virtual void Update(const std::string& key, const std::string& value,
                      const int previous_index, const UpdateCallback& cb);

  virtual void Delete(const std::string& key, const int current_index,
                      const DeleteCallback& cb);

 protected:
  EtcdClient();  // Testing only

  virtual void Generic(const std::string& key,
                       const std::map<std::string, std::string>& params,
                       evhttp_cmd_type verb, const GenericCallback& cb);

 private:
  typedef std::map<std::pair<std::string, uint16_t>,
                   boost::shared_ptr<libevent::HttpConnection> > ConnectionMap;

  struct Request {
    Request(EtcdClient* client, evhttp_cmd_type verb, const std::string& path,
            const std::string& params, const GenericCallback& cb)
        : client_(client), verb_(verb), path_(path), params_(params), cb_(cb) {}

    void Run(const boost::shared_ptr<libevent::HttpConnection>& conn) {
      libevent::HttpRequest* const req(new libevent::HttpRequest(
          bind(&EtcdClient::RequestDone, client_, _1, this)));

      std::string uri(path_);
      if (verb_ == EVHTTP_REQ_GET) {
        uri += "?" + params_;
      } else {
        evhttp_add_header(evhttp_request_get_output_headers(req->get()),
                          "Content-Type", "application/x-www-form-urlencoded");
        CHECK_EQ(evbuffer_add(evhttp_request_get_output_buffer(req->get()),
                              params_.data(), params_.size()),
                 0);
      }

      conn->MakeRequest(req, verb_, uri.c_str());
    }

    EtcdClient* const client_;
    const evhttp_cmd_type verb_;
    const std::string path_;
    const std::string params_;
    const GenericCallback cb_;
  };

  // If MaybeUpdateLeader returns true, the handling of the response
  // should be aborted, as a new leader was found, and the request has
  // been retried on the new leader.
  bool MaybeUpdateLeader(libevent::HttpRequest* req, Request* etcd_req);
  void RequestDone(libevent::HttpRequest* req, Request* etcd_req);

  void GetRequestDone(Status status, const boost::shared_ptr<JsonObject>&,
                      const GetCallback& cb) const;
  void GetAllRequestDone(Status status, const boost::shared_ptr<JsonObject>&,
                         const GetAllCallback& cb) const;
  void CreateRequestDone(Status status, const boost::shared_ptr<JsonObject>&,
                         const CreateCallback& cb) const;
  void CreateInQueueRequestDone(Status status,
                                const boost::shared_ptr<JsonObject>&,
                                const CreateInQueueCallback& cb) const;
  void UpdateRequestDone(Status status, const boost::shared_ptr<JsonObject>&,
                         const UpdateCallback& cb) const;
  void DeleteRequestDone(Status status, const boost::shared_ptr<JsonObject>&,
                         const DeleteCallback& cb) const;

  boost::shared_ptr<libevent::HttpConnection> GetConnection(
      const std::string& host, uint16_t port);

  const boost::shared_ptr<libevent::Base> event_base_;

  boost::mutex lock_;
  ConnectionMap conns_;
  // Last known leader.
  boost::shared_ptr<libevent::HttpConnection> leader_;

  friend class EtcdTest;
  DISALLOW_COPY_AND_ASSIGN(EtcdClient);
};

}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_ETCD_H_
