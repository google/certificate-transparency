#ifndef CERT_CHECKER_H
#define CERT_CHECKER_H

#include <openssl/x509.h>
#include <string>
#include <vector>

#include "log/cert.h"

namespace ct {
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
 CertChecker();

  ~CertChecker();

  enum CertVerifyResult {
    OK,
    // Until we know what the precise cert chain policy is, bag all chain errors
    // into INVALID_CERTIFICATE_CHAIN.
    INVALID_CERTIFICATE_CHAIN,
    PRECERT_CHAIN_NOT_WELL_FORMED,
    ROOT_NOT_IN_LOCAL_STORE,
    INTERNAL_ERROR,
    PRECERT_EXTENSION_IN_CERT_CHAIN,
  };

  // Load a file of concatenated PEM-certs.
  bool LoadTrustedCertificates(const std::string &trusted_cert_file);

  // Load a directory location.
  bool LoadTrustedCertificateDir(const std::string &trusted_cert_dir);

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
  CertVerifyResult CheckCertChain(CertChain *chain) const;

  // Check that:
  // (1) The PreCertChain is well-formed according to I-D rules.
  // (2) Each certificate is correctly signed by the next one in the chain; and
  // (3) The last certificate is issued by a certificate in our trusted store.
  // If verification succeeds, add the last self-signed cert to the chain
  // (or replace with store version) - the resulting chain is guaranteed to
  // contain at least two certificates (three if there is a Precert Signing
  // Certificate);
  // If valid, also fills in the |issuer_key_hash| and |tbs_certificate|.
  CertVerifyResult CheckPreCertChain(PreCertChain *chain,
                                     std::string* issuer_key_hash,
                                     std::string *tbs_certificate) const;

 private:
  CertVerifyResult CheckIssuerChain(CertChain *chain) const;
  // Look issuer up from the trusted store, and verify signature.
  CertVerifyResult GetTrustedCa(CertChain *chain) const;

  X509_STORE *trusted_;
};

}  // namespace ct
#endif
