#include "fetcher/peer.h"

#include <glog/logging.h>

namespace cert_trans {


Peer::Peer(AsyncLogClient* client) : client_(CHECK_NOTNULL(client)) {
}


}  // namespace cert_trans
