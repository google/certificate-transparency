#ifndef CERT_TRANS_SERVER_HANDLER_H_
#define CERT_TRANS_SERVER_HANDLER_H_

#include <memory>
#include <mutex>
#include <stdint.h>
#include <string>

#include "proto/ct.pb.h"
#include "util/libevent_wrapper.h"
#include "util/sync_task.h"
#include "util/task.h"

class Frontend;
template <class T>
class LogLookup;
template <class T>
class ReadOnlyDatabase;

namespace cert_trans {

class CertChain;
class CertChecker;
template <class T>
class ClusterStateController;
class JsonOutput;
class LoggedCertificate;
class PreCertChain;
class Proxy;
class ThreadPool;

using ct::SignedCertificateTimestamp;

class HttpHandler {
 public:
  // Does not take ownership of its parameters, which must outlive
  // this instance. The "frontend" parameter can be NULL, in which
  // case this server will not accept "add-chain" and "add-pre-chain"
  // requests.
  HttpHandler(JsonOutput* json_output,
              LogLookup<LoggedCertificate>* log_lookup,
              const ReadOnlyDatabase<LoggedCertificate>* db,
              const ClusterStateController<LoggedCertificate>* controller,
              const CertChecker* cert_checker, Frontend* frontend,
              Proxy* proxy, ThreadPool* pool, libevent::Base* event_base);
  virtual ~HttpHandler();

  virtual void Add(libevent::HttpServer* server) = 0;

  virtual void GetEntries(evhttp_request* req) const = 0;
  virtual void GetRoots(evhttp_request* req) const = 0;
  virtual void GetProof(evhttp_request* req) const = 0;
  virtual void GetSTH(evhttp_request* req) const = 0;
  virtual void GetConsistency(evhttp_request* req) const = 0;
  virtual void AddChain(evhttp_request* req) = 0;
  virtual void AddPreChain(evhttp_request* req) = 0;

  virtual void BlockingGetEntries(evhttp_request* req, int64_t start,
                                  int64_t end, bool include_scts) const = 0;
  virtual void BlockingAddChain(
      evhttp_request* req, const std::shared_ptr<CertChain>& chain) = 0;
  virtual void BlockingAddPreChain(
      evhttp_request* req,
      const std::shared_ptr<PreCertChain>& chain) = 0;

 protected:
  bool ExtractChain(JsonOutput* output, evhttp_request* req, CertChain* chain);
  void AddChainReply(JsonOutput* output, evhttp_request* req,
                     const util::Status& add_status,
                     const SignedCertificateTimestamp& sct);
  void ProxyInterceptor(
      const libevent::HttpServer::HandlerCallback& next_handler,
      evhttp_request* request);
  void AddProxyWrappedHandler(
      libevent::HttpServer* server, const std::string& path,
      const libevent::HttpServer::HandlerCallback& local_handler);
  std::multimap<std::string, std::string> ParseQuery(evhttp_request* req) const;
  bool GetParam(const std::multimap<std::string, std::string>& query,
                const std::string& param, std::string* value) const;
  int64_t GetIntParam(const std::multimap<std::string, std::string>& query,
                      const std::string& param) const;
  bool GetBoolParam(const std::multimap<std::string, std::string>& query,
                    const std::string& param) const;
  int GetMaxLeafEntriesPerResponse() const;

  JsonOutput* const output_;
  LogLookup<LoggedCertificate>* const log_lookup_;
  const ReadOnlyDatabase<LoggedCertificate>* const db_;
  const ClusterStateController<LoggedCertificate>* const controller_;
  const CertChecker* const cert_checker_;
  Frontend* const frontend_;
  Proxy* const proxy_;
  ThreadPool* const pool_;
  libevent::Base* const event_base_;

 private:

  bool IsNodeStale() const;
  void UpdateNodeStaleness();

  util::SyncTask task_;
  mutable std::mutex mutex_;
  bool node_is_stale_;

  DISALLOW_COPY_AND_ASSIGN(HttpHandler);
};


}  // namespace cert_trans

#endif  // CERT_TRANS_SERVER_HANDLER_H_
