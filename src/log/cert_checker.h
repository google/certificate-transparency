#ifndef CERT_CHECKER_H
#define CERT_CHECKER_H

#include <openssl/x509.h>
#include <string>
#include <vector>

#include "cert.h"

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

  bool LoadTrustedCertificate(const std::string &trusted_cert_file);

  bool LoadTrustedCertificateDir(const std::string &trusted_cert_dir);

  // TODO: return something more meaningful than a bool?

  // Check that:
  // (1) Each certificate is correctly signed by the next one in the chain; and
  // (2) The last certificate is issued by a certificate in our trusted store.
  // We do not check that the certificates are otherwise valid. In particular,
  // we accept certificates that have expired, are not yet valid, or have
  // critical extensions we do not recognize.
  bool CheckCertChain(const CertChain &chain) const;

  // Check that:
  // (1) The leaf certificate contains the critical poison extension.
  // (2) The next certificate in the chain is CA:FALSE and contains
  //     the Extended Key Usage extension for CT.
  // (3) The leaf is correctly signed by the second certificate.
  // (4) The chain starting with the second certificate is valid (protocerts are
  //     coming directly from CAs, so we can safely reject invalid submissions).
  // (5) The last certificate is issued by a certificate in our trusted store.
  bool CheckProtoCertChain(const ProtoCertChain &proto_chain) const;

 private:
  // Look issuer up from the trusted store, and verify signature.
  bool VerifyTrustedCaSignature(const Cert &subject) const;
  // Verify the certificate chain according to standard rules, except
  // start verification from the ca_protocert.
  bool VerifyProtoCaChain(const ProtoCertChain &chain) const;

  X509_STORE *trusted_;
};
#endif
