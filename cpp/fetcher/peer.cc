#include "fetcher/peer.h"

#include <glog/logging.h>

using std::unique_ptr;

namespace cert_trans {


Peer::Peer(unique_ptr<AsyncLogClient>&& client) : client_(move(client)) {
  CHECK(client_);
}


}  // namespace cert_trans
