#include "log/logged_certificate.h"
#include "log/strict_consistent_store-inl.h"

namespace cert_trans {
template class StrictConsistentStore<LoggedCertificate>;
}  // namespace cert_trans
