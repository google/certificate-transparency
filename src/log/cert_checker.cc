/* -*- indent-tabs-mode: nil -*- */
#include <glog/logging.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>
#include <vector>

#include "log/cert.h"
#include "log/cert_checker.h"
#include "util/openssl_util.h"  // for LOG_ALL_OPENSSL_ERRORS
#include "util/util.h"

CertChecker::CertChecker() : trusted_(NULL) {
}

CertChecker::~CertChecker() {
  if (trusted_ != NULL)
    X509_STORE_free(trusted_);
}

bool CertChecker::LoadTrustedCertificates(const std::string &cert_file) {
  if (trusted_ == NULL && ((trusted_ = X509_STORE_new()) == NULL)) {
    LOG(ERROR) << "Failed to initialize trusted cert store";
    LOG_OPENSSL_ERRORS(ERROR);
    return false;
  }

  if (X509_STORE_load_locations(trusted_, cert_file.c_str(), NULL) != 1) {
    LOG(ERROR) << "Failed to load trusted cert file";
    LOG_OPENSSL_ERRORS(ERROR);
    return false;
  }
  return true;
}

bool CertChecker::LoadTrustedCertificateDir(const std::string &cert_dir) {
  if (trusted_ == NULL && ((trusted_ = X509_STORE_new()) == NULL)) {
    LOG(ERROR) << "Failed to initialize trusted cert store";
    LOG_OPENSSL_ERRORS(ERROR);
    return false;
  }
  if (X509_STORE_load_locations(trusted_, NULL, cert_dir.c_str()) != 1) {
   LOG(ERROR) << "Failed to load trusted cert file";
    LOG_OPENSSL_ERRORS(ERROR);
    return false;
  }
  return true;
}

CertChecker::CertVerifyResult
CertChecker::CheckCertChain(CertChain *chain) const {
  if (chain == NULL || !chain->IsLoaded())
    return INVALID_CERTIFICATE_CHAIN;

  if (chain->RemoveCertsAfterFirstSelfSigned() != Cert::TRUE) {
    LOG(ERROR) << "Failed to trim chain";
    return INTERNAL_ERROR;
  }

  Cert::Status status = chain->IsValidCaIssuerChain();
  if (status == Cert::FALSE)
    return INVALID_CERTIFICATE_CHAIN;
  if (status != Cert::TRUE) {
    LOG(ERROR) << "Failed to check issuer chain";
    return INTERNAL_ERROR;
  }

  status = chain->IsValidSignatureChain();
  if (status == Cert::FALSE)
    return INVALID_CERTIFICATE_CHAIN;
  if (status != Cert::TRUE) {
    LOG(ERROR) << "Failed to check signature chain";
    return INTERNAL_ERROR;
  }
  return GetTrustedCa(chain);
}

CertChecker::CertVerifyResult
CertChecker::CheckPreCertChain(PreCertChain *chain) const {
  if (chain == NULL || !chain->IsLoaded())
    return INVALID_CERTIFICATE_CHAIN;
  Cert::Status status = chain->IsWellFormed();
  if (status == Cert::FALSE)
    return PRECERT_CHAIN_NOT_WELL_FORMED;
  if (status != Cert::TRUE) {
    LOG(ERROR) << "Failed to check precert chain format";
    return INTERNAL_ERROR;
  }
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
  if (chain->Length() < 2 ||
      (chain->UsesPrecertSigningCertificate() == Cert::TRUE &&
       chain->Length() < 3)) {
    LOG(ERROR) << "CertChecker produced a precert chain that is too short";
    return INTERNAL_ERROR;
  }
return OK;
}

CertChecker::CertVerifyResult
CertChecker::GetTrustedCa(CertChain *chain) const {
  const Cert *subject = chain->LastCert();
  if (subject == NULL || !subject->IsLoaded()) {
    LOG(ERROR) << "Chain has no valid certs";
    return INTERNAL_ERROR;
  }

  // Look up issuer from the trusted store.
  if (trusted_ == NULL) {
    LOG(WARNING) << "No trusted certificates loaded";
    return ROOT_NOT_IN_LOCAL_STORE;
  }

  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  if (ctx == NULL) {
    LOG_OPENSSL_ERRORS(ERROR);
    return INTERNAL_ERROR;
  }

  int ret = X509_STORE_CTX_init(ctx, trusted_, NULL, NULL);
  if (ret != 1) {
    X509_STORE_CTX_free(ctx);
    LOG_OPENSSL_ERRORS(ERROR);
    return INTERNAL_ERROR;
  }

  X509 *issuer_x509 = NULL;
  // Attempt to find the correct issuer: if multiple issuers with
  // the same subject but different keys exist in store,
  // X509_STORE_CTX_get1_issuer should be able to distinguish based on
  // Authority KeyID.
  ret = X509_STORE_CTX_get1_issuer(&issuer_x509, ctx, subject->x509_);
  X509_STORE_CTX_free(ctx);
  if (ret == 0)
    return ROOT_NOT_IN_LOCAL_STORE;
  if (ret < 0) {
    LOG_OPENSSL_ERRORS(ERROR);
    return INTERNAL_ERROR;
  }

 // get1 ups the refcount, so this is safe.
  Cert issuer(issuer_x509);

  // TODO(ekasper): check that the issuing CA cert is temporally valid.
  // TODO(ekasper): do we need to run any other checks on the issuer?
  if (!issuer.IsLoaded()) {
    LOG(ERROR) << "Failed to load store issuer";
    return INTERNAL_ERROR;
  }

  // If last cert is self-signed, skip signature check but do check we have an
  // exact match.
  Cert::Status status = subject->IsSelfSigned();
  if (status != Cert::TRUE && status != Cert::FALSE) {
    LOG(ERROR) << "Failed to check self-signed status";
    return INTERNAL_ERROR;
  }
  if (status == Cert::TRUE) {
    Cert::Status matches = subject->IsIdenticalTo(issuer);
    if (matches != Cert::TRUE && matches != Cert::FALSE) {
      LOG(ERROR) << "Cert comparison failed";
      return INTERNAL_ERROR;
    }
    if (matches != Cert::TRUE) {
      return ROOT_NOT_IN_LOCAL_STORE;
    }
  } else {
    Cert::Status ok = subject->IsSignedBy(issuer);
    if (ok != Cert::TRUE && status != Cert::FALSE) {
      LOG(ERROR) << "Failed to check signature for trusted root";
      return INTERNAL_ERROR;
    }
    if (ok != Cert::TRUE) {
      return ROOT_NOT_IN_LOCAL_STORE;
    }

    // Clone creates a new Cert but AddCert takes ownership even if Clone
    // failed and the cert can't be added, so we don't have to explicitly
    // check for IsLoaded here.
    if (chain->AddCert(issuer.Clone()) != Cert::TRUE) {
      LOG(ERROR) << "Failed to add trusted root to chain";
      return INTERNAL_ERROR;
    }
  }
  return OK;
}
