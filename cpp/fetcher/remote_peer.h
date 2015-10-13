#ifndef CERT_TRANS_FETCHER_REMOTE_PEER_H_
#define CERT_TRANS_FETCHER_REMOTE_PEER_H_

#include <memory>

#include "fetcher/peer.h"
#include "log/log_verifier.h"
#include "util/task.h"

namespace cert_trans {

class LoggedCertificate;


class RemotePeer : public Peer {
 public:
  // The "task" will return when the object is fully destroyed
  // (destroying this object starts the asynchronous destruction).
  // |on_new_sth| will be called for each new STH that this object sees from
  // the target log.
  RemotePeer(std::unique_ptr<AsyncLogClient> client,
             std::unique_ptr<LogVerifier> verifier,
             const std::function<void(const ct::SignedTreeHead&)>& on_new_sth,
             util::Task* task);
  ~RemotePeer() override;

  int64_t TreeSize() const override;

 private:
  struct Impl;

  std::unique_ptr<Impl> const impl_;
};


}  // namespace cert_trans

#endif  // CERT_TRANS_FETCHER_REMOTE_PEER_H_
