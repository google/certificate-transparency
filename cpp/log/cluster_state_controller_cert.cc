#include "log/cluster_state_controller-inl.h"
#include "log/logged_certificate.h"

namespace cert_trans {
template class ClusterStateController<LoggedCertificate>;
}  // namespace cert_trans
