#include <assert.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>
#include <vector>

#include "cert.h"
#include "cert_checker.h"

CertChecker::CertChecker() : trusted_(NULL) {
  trusted_ = X509_STORE_new();
  assert(trusted_ != NULL);
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

bool CertChecker::CheckCertChain(const CertChain &chain) const {
  assert(chain.IsLoaded());
  if (!chain.IsValidIssuerChain() || !chain.IsValidSignatureChain())
    return false;
  return VerifyTrustedCaSignature(*chain.LastCert());
}

bool CertChecker::CheckProtoCertChain(const ProtoCertChain &chain) const {
  assert(chain.IsLoaded());
  if (!chain.IsWellFormed())
    return false;

  // Check that the chain is valid.
  // OpenSSL does not enforce an ordering of the chain, so check that the
  // chain (appears to be) ordered correctly.
  // Only check the signature on the leaf certificate (full verification would
  // fail since the leaf contains an unrecognized critical extension).
  const Cert *proto = chain.ProtoCert();
  const Cert *proto_ca = chain.CaProtoCert();
  return proto->IsSignedBy(*proto_ca) && chain.IsValidIssuerChain() &&
      VerifyProtoCaChain(chain);
}

bool CertChecker::VerifyTrustedCaSignature(const Cert &subject) const {
  // Look up issuer from the trusted store.
  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  assert(ctx != NULL);
  int ret = X509_STORE_CTX_init(ctx, trusted_, NULL, NULL);
  assert(ret == 1);
  X509_OBJECT obj;
  // TODO: we may need to do something more clever, in case there is
  // more than one match.
  ret = X509_STORE_get_by_subject(ctx,X509_LU_X509,
                                  X509_get_issuer_name(subject.x509_), &obj);
  X509_STORE_CTX_free(ctx);
  if (ret <= 0)
    return false;

  // X509_STORE_get_by_subject increments the ref count.
  // Pass ownership to the cert object.
  Cert issuer(obj.data.x509);
  // X509_STORE_get_by_subject increments ref count.
  X509_OBJECT_free_contents(&obj);
  assert(issuer.IsLoaded());
  // TODO: do we need to do any other checks on issuer?
  return subject.IsSignedBy(issuer);
}

bool CertChecker::VerifyProtoCaChain(const ProtoCertChain &chain) const {
  assert(chain.IsLoaded());
  X509 *leaf = chain.CaProtoCert()->x509_;
  assert(leaf != NULL);
  // The remaining certificates.
  STACK_OF(X509) *intermediates = NULL;
  if (chain.IntermediateLength() > 0) {
    intermediates = sk_X509_new_null();
    assert(intermediates != NULL);
    for (size_t pos = 0; pos < chain.IntermediateLength(); ++pos)
      sk_X509_push(intermediates, chain.IntermediateAt(pos)->x509_);
  }

  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  assert(ctx != NULL);
  int ret = X509_STORE_CTX_init(ctx, trusted_, leaf, intermediates);
  assert(ret == 1);

  ret = X509_verify_cert(ctx);

  X509_STORE_CTX_free(ctx);
  if (intermediates != NULL)
    sk_X509_free(intermediates);

  return ret == 1;
}
