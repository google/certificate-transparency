/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef CERT_CHECKER_H
#define CERT_CHECKER_H

#include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <map>
#include <string>
#include <vector>

#include "base/macros.h"
#include "log/cert.h"

namespace cert_trans {

class Cert;
class CertChain;
class PreCertChain;

// A class for doing sanity-checks on log submissions before accepting them.
// We don't necessarily want to do full certificate verification
// before accepting them. E.g., we may want to accept submissions of
// invalid (say, expired) certificates directly from clients,
// to detect attacks after the fact. We primarily only
// want to check that submissions chain to a whitelisted CA, so that
// (1) we know where a cert is coming from; and
// (2) we get some spam protection.
class CertChecker {
 public:
  CertChecker() = default;

  virtual ~CertChecker();

  enum CertVerifyResult {
    OK,
    // Until we know what the precise cert chain policy is, bag all
    // chain errors into INVALID_CERTIFICATE_CHAIN.
    INVALID_CERTIFICATE_CHAIN,
    PRECERT_CHAIN_NOT_WELL_FORMED,
    ROOT_NOT_IN_LOCAL_STORE,
    INTERNAL_ERROR,
    PRECERT_EXTENSION_IN_CERT_CHAIN,
    UNSUPPORTED_ALGORITHM_IN_CERT_CHAIN,
  };

  // Load a file of concatenated PEM-certs.
  // Returns true if at least one certificate was successfully loaded, and no
  // errors were encountered. Returns false otherwise (and will not load any
  // certificates from this file).
  virtual bool LoadTrustedCertificates(const std::string& trusted_cert_file);

  // Load directly from |trusted_certs|, a vector of PEM-certs.
  // Returns true if at least one of the supplied certs was loaded successfully.
  virtual bool LoadTrustedCertificates(
      const std::vector<std::string>& trusted_certs);

  virtual void ClearAllTrustedCertificates();

  virtual const std::multimap<std::string, const Cert*>&
  GetTrustedCertificates() const {
    return trusted_;
  }

  virtual size_t NumTrustedCertificates() const { return trusted_.size(); }

  // Checks that a CMS_ContentInfo has a signer that matches a specified
  // certificate. Does not verify the signature or check the payload.
  virtual Cert::Status IsCmsSignedByCert(CMS_ContentInfo* cms,
                                         const Cert& cert) const;

  // Unpacks a CMS signed data object that is assumed to contain a certificate
  // If the CMS signature verifies then we return a corresponding new Cert
  // object built from the unpacked data. If it cannot be loaded as a
  // certificate or fails CMS signing check then an unloaded empty Cert object
  // is returned. The input BIO is freed. The caller owns the returned
  // certificate.
  // NOTE: Certificate chain validity checks must be done separately. This
  // only checks that the CMS signature is valid.
  virtual Cert* UnpackCmsSignedCertificate(BIO* cms_bio_in,
                                           const CertChain& certChain);

  // Check that:
  // (1) Each certificate is correctly signed by the next one in the chain; and
  // (2) The last certificate is issued by a certificate in our trusted store.
  // We do not check that the certificates are otherwise valid. In particular,
  // we accept certificates that have expired, are not yet valid, or have
  // critical extensions we do not recognize.
  // If verification succeeds, add the last self-signed cert to the chain
  // (or replace with store version) - the resulting chain is guaranteed to
  // contain at least one certificate. (Having exactly one certificate implies
  // someone is trying to log a root cert, which is fine though unexciting.)
  virtual CertVerifyResult CheckCertChain(CertChain* chain) const;

  // Check that:
  // (1) The PreCertChain is well-formed according to I-D rules.
  // (2) Each certificate is correctly signed by the next one in the chain; and
  // (3) The last certificate is issued by a certificate in our trusted store.
  // If verification succeeds, add the last self-signed cert to the chain
  // (or replace with store version) - the resulting chain is guaranteed to
  // contain at least two certificates (three if there is a Precert Signing
  // Certificate);
  // If valid, also fills in the |issuer_key_hash| and |tbs_certificate|.
  virtual CertVerifyResult CheckPreCertChain(
      PreCertChain* chain, std::string* issuer_key_hash,
      std::string* tbs_certificate) const;

 private:
  CertVerifyResult CheckIssuerChain(CertChain* chain) const;
  // Look issuer up from the trusted store, and verify signature.
  CertVerifyResult GetTrustedCa(CertChain* chain) const;

  // Returns OK if the cert is trusted, ROOT_NOT_IN_LOCAL_STORE if it's not,
  // INVALID_CERTIFICATE_CHAIN if something is wrong with the cert, and
  // INTERNAL_ERROR if something terrible happened.
  CertVerifyResult IsTrusted(const Cert& cert, std::string* subject_name) const;

  // Verifies that data from a DER BIO is signed by a cert in a chain.
  // and writes the unwrapped content to another BIO. NULL can be passed for
  // cms_bio_out if the caller just wishes to verify the signature. Does
  // not free either BIO. Does not do any checks on the content of the
  // CMS message or validate that the CMS signature is trusted to root.
  virtual Cert::Status UnpackCmsDerBio(BIO* cms_bio_in,
                                       const CertChain& certChain,
                                       BIO* cms_bio_out);

  // A map by the DER encoding of the subject name.
  // All code manipulating this container must ensure contained elements are
  // deallocated appropriately.
  std::multimap<std::string, const Cert*> trusted_;

  // Helper for LoadTrustedCertificates, whether reading from file or memory.
  // Takes ownership of bio_in and frees it.
  bool LoadTrustedCertificatesFromBIO(BIO* bio_in);

  DISALLOW_COPY_AND_ASSIGN(CertChecker);
};

}  // namespace cert_trans

#endif
