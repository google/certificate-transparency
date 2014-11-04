#include "log/fake_consistent_store-inl.h"
#include "log/logged_certificate.h"

namespace cert_trans {
template class FakeConsistentStore<LoggedCertificate>;
}  // namespace cert_trans
