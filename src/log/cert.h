#ifndef CERT_H
#define CERT_H

#include <assert.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <string>
#include <vector>

#include "types.h"

class Cert {
 public:
  // The proof extension in a superfluous certificate.
  static const char kProofExtensionOID[];
  // The embedded proof extension.
  static const char kEmbeddedProofExtensionOID[];
  // The poison extension in the PreCert (critical).
  static const char kPoisonExtensionOID[];
  // The Certificate Transparency Extended Key Usage OID
  // (indicating that a certificate can be used for precert signing
  // on behalf of the issuing CA)
  static const char kCtExtendedKeyUsageOID[];

  static ASN1_OBJECT *ExtensionObject(const std::string oid);
  // Does not take ownership of the X509 object; makes a local copy.
  explicit Cert(X509 *x509);
  // May fail, but we don't want to die on invalid inputs,
  // so caller should check IsLoaded() before doing anything else.
  // Right now we don't offer a way to recover from failure,
  // so all subsequent attempts to operate on unloaded certs will fail.
  explicit Cert(const std::string &pem_string);
  ~Cert();

  bool IsLoaded() const { return x509_ != NULL; }

  Cert *Clone() const;

  bool HasExtension(const std::string &extension_oid) const;

  bool HasExtension(int nid) const;

  bool IsCriticalExtension(const std::string &extension_oid) const;

  bstring ExtensionData(const std::string &extension_oid) const;

  bool HasBasicConstraintCA() const;

  bool HasExtendedKeyUsage(const std::string &key_usage_oid) const;

  bool IsIssuedBy(const Cert &issuer) const;

  bool IsSignedBy(const Cert &issuer) const;

  bstring DerEncoding() const;

  // WARNING WARNING The following methods modify the x509_ structure
  // and thus invalidate the cert.
  // They are mostly needed for processing precerts. Use with care.

  // Delete the matching extension, if present.
  void DeleteExtension(const std::string &extension_oid);

  void DeleteExtension(int extension_nid);

  // Delete signature, if present.
  void DeleteSignature();

  // Copy the issuer.
  void CopyIssuerFrom(const Cert &from);

  // CertChecker needs access to the x509_ structure directly.
  friend class CertChecker;
 private:
  // Returns the index of a matching extension, or -1 for 'not found'.
  int ExtensionIndex(const std::string &extension_oid) const;
  int ExtensionIndex(int extension_nid) const;
  // Returns a pointer to a matching extension, or NULL for 'not found'.
  X509_EXTENSION *GetExtension(const std::string &extension_oid) const;
  X509_EXTENSION *GetExtension(int extension_nid) const;

  X509 *x509_;
};

class CertChain {
 public:
  CertChain() {}
  // Will fail on any parsing error.
  // Caller should check IsLoaded() before doing anything else.
  explicit CertChain(const std::string &pem_string);
  ~CertChain();

  // Add a cert to the end of the chain.
  void AddCert(Cert *cert);

  // Remove a cert from the end of the chain.
  void RemoveCert();

  // True if the chain loaded correctly, and contains at least one valid cert.
  bool IsLoaded() const { return !chain_.empty(); }

  size_t Length() const {
    assert(IsLoaded());
    return chain_.size();
  }

  Cert const *LeafCert() const {
    assert(IsLoaded());
    return chain_.front();
  }

  Cert const *CertAt(size_t position) const {
    return chain_.size() <= position ? NULL : chain_[position];
  }

  Cert const *LastCert() const {
    assert(IsLoaded());
    return chain_.back();
  }

  // True if the issuer of each cert is the subject of the next cert.
  bool IsValidIssuerChain() const;

  // True if each cert is signed by the next one.
  bool IsValidSignatureChain() const;

 protected:

 private:
  void ClearChain();
  std::vector<Cert*> chain_;
};

class PreCertChain : public CertChain {
 public:
  PreCertChain() {}

  explicit PreCertChain(const std::string &pem_string)
      : CertChain(pem_string) {}

  // Some convenient aliases.
  // A pointer to the precert.
  Cert const *PreCert() const {
    return LeafCert();
  }

  // A pointer to the issuing CA precert.
  Cert const *CaPreCert() const {
    return Length() >= 2 ? CertAt(1) : NULL;
  }

  // The chain is precert -- ca_precert -- intermediates
  size_t IntermediateLength() const {
    assert(IsLoaded());
    return Length() < 2 ? 0 : Length() - 2;
  }

  Cert const *IntermediateAt(size_t position) const {
    assert(IsLoaded());
    if (IntermediateLength() <= position)
      return NULL;
    return CertAt(position + 2);
  }

  // True if
  // (1) The chain contains at least two certificates.
  // (1) The leaf certificate contains the critical poison extension.
  // (2) The next certificate in the chain is CA:FALSE and contains
  //     the Extended Key Usage extension for CT.
  // (3) The leaf is issued by the second certificate.
  // (4) Both certs have an Authority KeyID extension.
  // This method does not verify any signatures, or otherwise check
  // that the chain is valid.
  bool IsWellFormed() const;
};
#endif
