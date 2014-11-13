#include "log/logged_certificate.h"
#include "log/tree_signer-inl.h"

namespace cert_trans {
template class TreeSigner<cert_trans::LoggedCertificate>;
}  // namespace cert_trans
