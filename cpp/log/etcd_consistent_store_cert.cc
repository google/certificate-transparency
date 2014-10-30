#include "log/etcd_consistent_store-inl.h"
#include "log/logged_certificate.h"

namespace cert_trans {
template class EtcdConsistentStore<LoggedCertificate>;
}  // namespace cert_trans
