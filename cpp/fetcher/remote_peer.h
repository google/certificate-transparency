#ifndef CERT_TRANS_FETCHER_REMOTE_PEER_H_
#define CERT_TRANS_FETCHER_REMOTE_PEER_H_

#include "fetcher/peer.h"
#include "log/log_verifier.h"
#include "util/task.h"

namespace cert_trans {


class RemotePeer : public Peer {
 public:
  // Takes ownership of "client" and "verifier". The "task" will
  // return when the object is fully destroyed (destroying this object
  // starts the asynchronous destruction).
  RemotePeer(AsyncLogClient* client, LogVerifier* verifier, util::Task* task);
  ~RemotePeer() override;

  int64_t TreeSize() const override;

 private:
  struct Impl;

  // This gets deleted via the util::Task.
  Impl* const impl_;
};


}  // namespace cert_trans

#endif  // CERT_TRANS_FETCHER_REMOTE_PEER_H_
