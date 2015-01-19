#include "log/etcd_consistent_store-inl.h"
#include "log/logged_certificate.h"

DEFINE_int32(node_state_ttl_seconds, 60,
             "TTL in seconds on the node state files.");

namespace cert_trans {
template class EtcdConsistentStore<LoggedCertificate>;
}  // namespace cert_trans
