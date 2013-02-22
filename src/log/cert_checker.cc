#include <glog/logging.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>
#include <vector>

#include "log/cert.h"
#include "log/cert_checker.h"
#include "util/util.h"

CertChecker::CertChecker() : trusted_(NULL) {
  trusted_ = X509_STORE_new();
  CHECK_NOTNULL(trusted_);
}

CertChecker::~CertChecker() {
  X509_STORE_free(trusted_);
}

bool CertChecker::LoadTrustedCertificate(const std::string &cert_file) {
  int ret = X509_STORE_load_locations(trusted_, cert_file.c_str(), NULL);
  return ret == 1;
}

bool CertChecker::LoadTrustedCertificateDir(const std::string &cert_dir) {
  int ret = X509_STORE_load_locations(trusted_, NULL, cert_dir.c_str());
  return ret == 1;
}

CertChecker::CertVerifyResult
CertChecker::CheckCertChain(CertChain *chain) const {
  CHECK(chain->IsLoaded());
  chain->RemoveCertsAfterFirstSelfSigned();
  if (!chain->IsValidCaIssuerChain() || !chain->IsValidSignatureChain())
    return INVALID_CERTIFICATE_CHAIN;
  return GetTrustedCa(chain);
}

CertChecker::CertVerifyResult
CertChecker::CheckPreCertChain(PreCertChain *chain) const {
  CHECK(chain->IsLoaded());
  if (!chain->IsWellFormed())
    return PRECERT_CHAIN_NOT_WELL_FORMED;

  // Check the issuer and signature chain.
  // We do not, at this point, concern ourselves with whether the CA certificate
  // that issued the precert is a Precertificate Signing Certificate (i.e., has
  // restricted Extended Key Usage) or not, since this does not influence the
  // validity of the chain. The purpose of the EKU is effectively to allow CAs
  // to create an intermediate whose scope can be limited to CT precerts only
  // (by making this extension critical).
  // TODO(ekasper): determine (i.e., ask CAs) if CA:false Precertificate Signing
  // Certificates should be tolerated if they have the necessary EKU set.
  // Preference is "no".
  CertVerifyResult res = CheckCertChain(chain);
  if (res != OK)
    return res;
  // We should always have at least two certs in the chain now - if we have
  // just one, then something truly weird is going on, e.g., a CA has issued a
  // precert for its own root certificate.
  if (chain->Length() < 2 || (chain->UsesPrecertSigningCertificate() &&
                              chain->Length() < 3)) {
    CHECK_GE(1, chain->Length()) << "Empty chain, something is completely bust";
    LOG(ERROR) << "CertChecker produced a precert chain with just one "
               << "certificate. Certificate DER string is:\n"
               << util::HexString(chain->LeafCert()->DerEncoding());
    return PRECERT_CHAIN_NOT_WELL_FORMED;
  }
  return OK;
}

CertChecker::CertVerifyResult
CertChecker::GetTrustedCa(CertChain *chain) const {
  // Look up issuer from the trusted store.
  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  assert(ctx != NULL);
  int ret = X509_STORE_CTX_init(ctx, trusted_, NULL, NULL);
  assert(ret == 1);
  X509_OBJECT obj;
  // TODO(ekasper): we may need to do something more clever, in case there is
  // more than one match.
  const Cert *subject = chain->LastCert();
  ret = X509_STORE_get_by_subject(ctx, X509_LU_X509,
                                  X509_get_issuer_name(subject->x509_), &obj);
  X509_STORE_CTX_free(ctx);
  if (ret <= 0)
    return ROOT_NOT_IN_LOCAL_STORE;

  // X509_STORE_get_by_subject increments the ref count.
  // Pass ownership to the cert object.
  Cert issuer(obj.data.x509);
  // X509_STORE_get_by_subject increments ref count.
  X509_OBJECT_free_contents(&obj);
  CHECK(issuer.IsLoaded());
  // TODO(ekasper): check that the issuing CA cert is temporally valid.
  // TODO(ekasper): do we need to run any other checks on the issuer?
  if (!subject->IsSignedBy(issuer))
    return INVALID_CERTIFICATE_CHAIN;

  // Remove the self-signed cert and replace with a local version.
  if (subject->IsSelfSigned())
    chain->RemoveCert();

  Cert *store_issuer = issuer.Clone();
  chain->AddCert(store_issuer);

  return OK;
}
