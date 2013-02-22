#ifndef CERT_H
#define CERT_H

#include <assert.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <string>
#include <vector>

class Cert {
 public:
  // superfluousCertificateExtension,
  // the proof extension in a superfluous certificate.
  static const char kProofExtensionOID[];
  // sctExtension, the embedded proof extension.
  static const char kEmbeddedProofExtensionOID[];
  // poisonExtension, the poison extension in the PreCert (critical).
  static const char kPoisonExtensionOID[];
  // precertificateSigning, The Certificate Transparency Extended Key Usage OID
  // (indicating that a certificate can be used for precert signing
  // on behalf of the issuing CA).
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

  // TODO(ekasper): comment all of these methods properly.

  bool IsLoaded() const { return x509_ != NULL; }

  Cert *Clone() const;

  bool HasExtension(const std::string &extension_oid) const;

  bool HasExtension(int nid) const;

  // Caller must always first check that the extension exists.
  bool IsCriticalExtension(const std::string &extension_oid) const;
  bool IsCriticalExtension(int extension_nid) const;

  // If the extension is a valid ASN.1-encoded octet string, writes the
  // (binary) contents (with the ASN.1 wrapping removed) to result and returns
  // true. Else returns false and leaves |result| unmodified.
  bool OctetStringExtensionData(const std::string &extension_oid,
                                std::string *result) const;

  bool HasBasicConstraintCA() const;

  bool HasExtendedKeyUsage(const std::string &key_usage_oid) const;

  bool IsIssuedBy(const Cert &issuer) const;

  bool IsSignedBy(const Cert &issuer) const;

  bool IsSelfSigned() const { return IsIssuedBy(*this); }

  // returns binary data
  std::string DerEncoding() const;

  std::string Sha256Digest() const;

  // The X509_CINF part of the cert.
  std::string DerEncodedTbsCertificate() const;

  std::string PublicKeySha256Digest() const;

  // WARNING WARNING The following methods modify the x509_ structure
  // and thus invalidate the cert.
  // They are mostly needed for processing precerts. Use with care.

  // Delete the matching extension, if present.
  void DeleteExtension(const std::string &extension_oid);

  void DeleteExtension(int extension_nid);

  // Delete signature, if present.
  void DeleteSignature();

  // Copy the issuer.
  bool CopyIssuerFrom(const Cert &from);

  // CertChecker needs access to the x509_ structure directly.
  friend class CertChecker;
 private:
  // Returns the index of a matching extension, or -1 for 'not found'.
  int ExtensionIndex(const std::string &extension_oid) const;
  int ExtensionIndex(int extension_nid) const;
  // Returns a pointer to a matching extension, or NULL for 'not found'.
  X509_EXTENSION *GetExtension(const std::string &extension_oid) const;
  X509_EXTENSION *GetExtension(int extension_nid) const;
  static bool IsCriticalExtension(X509_EXTENSION *ext);

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
  // Takes ownership of the cert.
  void AddCert(Cert *cert);

  // Remove a cert from the end of the chain.
  void RemoveCert();

  // Keep the first self-signed, remove the rest. We keep the first one so that
  // chains consisting only of a self-signed cert don't become invalid.
  void RemoveCertsAfterFirstSelfSigned();

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

  // True if the issuer of each cert is the subject of the next cert,
  // and each issuer has BasicConstraints CA:true.
  bool IsValidCaIssuerChain() const;

  // True if each cert is signed by the next one.
  bool IsValidSignatureChain() const;

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

  // A pointer to the issuing cert, which is either the issuing CA cert,
  // or a special-purpose Precertificate Signing Certificate issued
  // directly by the CA cert.
  // Can be NULL if the precert is issued directly by a root CA.
  Cert const *PrecertIssuingCert() const {
    return Length() >= 2 ? CertAt(1) : NULL;
  }

  bool UsesPrecertSigningCertificate() const;

  // True if
  // (1) the leaf certificate contains the critical poison extension;
  // TODO(ekasper): sync the requirements here with doc changes in
  // https://codereview.appspot.com/7303098/
  // (2) if the leaf certificate issuing certificate is present and has the
  //     CT EKU, and the leaf certificate has an Authority KeyID extension,
  //     then its issuing certificate also has this extension.
  //     In this case, also check that both extensions are correctly marked
  //     as non-critical.
  // (2) is necessary for the log to be able to "predict" the AKID of the final
  // TbsCertificate.
  // This method does not verify any signatures, or otherwise check
  // that the chain is valid.
  bool IsWellFormed() const;
};
#endif
