/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef CERT_H
#define CERT_H
#include <gtest/gtest_prod.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <string>
#include <vector>

#include "base/macros.h"

namespace cert_trans {

// Tests if a hostname contains any redactions ('?' elements). If it does
// not then there is no need to apply the validation below
bool IsRedactedHost(const std::string& hostname);
// Tests if a hostname containing any redactions follows the RFC rules
bool IsValidRedactedHost(const std::string& hostname);

class Cert {
 public:
  // Takes ownership of the X509 structure. It's advisable to check
  // IsLoaded() after construction to verify the copy operation succeeded.
  explicit Cert(X509* x509);
  // May fail, but we don't want to die on invalid inputs,
  // so caller should check IsLoaded() before doing anything else.
  // All attempts to operate on an unloaded cert will fail with ERROR.
  explicit Cert(const std::string& pem_string);
  Cert() : x509_(NULL) {
  }
  ~Cert();

  enum Status {
    TRUE,
    // OpenSSL makes it very hard to distinguish between input errors
    // (cert somehow corrupt) and internal library errors (malloc errors,
    // improper library initialization errors etc), hence the only errors
    // we currently report are caller errors where the Cert is not loaded
    // (and thus the method should not have been called in the first place),
    // or the NID is not recognized, as well as some obvious internal errors.
    // Any ops on certs that may have failed because the cert was malformed
    // return FALSE unless we can track the failure down to OpenSSL with
    // certainty.
    FALSE,
    ERROR,
    // This can happen when an algorithm is not accepted (e.g. MD2).
    // We signal UNSUPPORTED_ALGORITHM rather than FALSE on signature
    // verification to indicate that the certificate signature is
    // unconditionally not accepted.
    UNSUPPORTED_ALGORITHM,
  };

  bool IsLoaded() const {
    return x509_ != NULL;
  }

  // Never returns NULL but check IsLoaded() after Clone to verify the
  // underlying copy succeeded.
  Cert* Clone() const;

  // Frees the old X509 and attempts to load a new one.
  Status LoadFromDerString(const std::string& der_string);

  // Frees the old X509 and attempts to load from BIO in DER form. Caller
  // still owns the BIO afterwards.
  Status LoadFromDerBio(BIO *bio_in);

  // These just return an empty string if an error occurs.
  std::string PrintIssuerName() const;
  std::string PrintSubjectName() const;
  std::string PrintNotBefore() const;
  std::string PrintNotAfter() const;
  std::string PrintSignatureAlgorithm() const;

  Status IsIdenticalTo(const Cert& other) const;

  // Returns TRUE if the extension is present.
  // Returns FALSE if the extension is not present.
  // Returns ERROR if the cert is not loaded, extension_nid is not recognised
  // or some other unknown error occurred while parsing the extensions.
  // NID must be either an OpenSSL built-in NID, or one registered by the user
  // with OBJ_create. (See log/ct_extensions.h for sample code.)
  Status HasExtension(int extension_nid) const;

  // Returns TRUE if the extension is present and critical.
  // Returns FALSE if the extension is not present, or is present but not
  // critical.
  // Returns ERROR if the cert is not loaded, extension_nid is not recognised
  // or some other unknown error occurred while parsing the extensions.
  // NID must be either an OpenSSL built-in NID, or one registered by the user
  // with OBJ_create. (See log/ct_extensions.h for sample code.)
  Status HasCriticalExtension(int extension_nid) const;

  // Returns TRUE if the basicConstraints extension is present and CA=TRUE.
  // Returns FALSE if the extension is not present, is present but CA=FALSE,
  // or is present but could not be decoded.
  // Returns ERROR if the cert is not loaded or some other unknown error
  // occurred while parsing the extensions.
  Status HasBasicConstraintCATrue() const;

  // Returns TRUE if extendedKeyUsage extension is present and the specified
  // key usage is set.
  // Returns FALSE if the extension is not present, is present but could not
  // be decoded, or is present but the specified key usage is not set.
  // Returns ERROR if the cert is not loaded, extension_nid is not recognised
  // or some other unknown error occurred while parsing the extensions.
  // NID must be either an OpenSSL built-in NID, or one registered by the user
  // with OBJ_create. (See log/ct_extensions.h for sample code.)
  Status HasExtendedKeyUsage(int key_usage_nid) const;

  // Returns TRUE if the Cert's issuer matches |issuer|.
  // Returns FALSE if there is no match.
  // Returns ERROR if either cert is not loaded.
  Status IsIssuedBy(const Cert& issuer) const;

  // Returns TRUE if the cert's signature can be verified by the issuer's
  // public key.
  // Returns FALSE if the signature cannot be verified.
  // Returns ERROR if either cert is not loaded or some other error occurs.
  // Does not check if issuer has CA capabilities.
  Status IsSignedBy(const Cert& issuer) const;

  Status IsSelfSigned() const {
    return IsIssuedBy(*this);
  }

  // Sets the DER encoding of the cert in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  Status DerEncoding(std::string* result) const;

  // Sets the PEM encoding of the cert in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  Status PemEncoding(std::string* result) const;

  // Sets the SHA256 digest of the cert in |result|.
  // Returns TRUE if computing the digest succeeded.
  // Returns FALSE if computing the digest failed.
  // Returns ERROR if the cert is not loaded.
  Status Sha256Digest(std::string* result) const;

  // Sets the DER-encoded TBS component of the cert in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  Status DerEncodedTbsCertificate(std::string* result) const;

  // Sets the DER-encoded subject Name component of the cert in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  Status DerEncodedSubjectName(std::string* result) const;

  // Sets the DER-encoded issuer Name component of the cert in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  Status DerEncodedIssuerName(std::string* result) const;

  // Sets the SHA256 digest of the cert's public key in |result|.
  // Returns TRUE if computing the digest succeeded.
  // Returns FALSE if computing the digest failed.
  // Returns ERROR if the cert is not loaded.
  Status PublicKeySha256Digest(std::string* result) const;

  // Sets the SHA256 digest of the cert's subjectPublicKeyInfo in |result|.
  // Returns TRUE if computing the digest succeeded.
  // Returns FALSE if computing the digest failed.
  // Returns ERROR if the cert is not loaded.
  Status SPKISha256Digest(std::string* result) const;

  // Fetch data from an extension if encoded as an ASN1_OCTET_STRING.
  // Useful for handling custom extensions registered with X509V3_EXT_add.
  // Returns true if the extension is present and the data could be decoded.
  // Returns false if the extension is not present or the data is not a valid
  // ASN1_OCTET_STRING.
  //
  // Caller MUST ensure that the registered type of the extension
  // contents is an ASN1_OCTET_STRING. Only use if you know what
  // you're doing.
  //
  // Returns TRUE if the extension data could be fetched and decoded.
  // Returns FALSE if the extension is not present, or is present but is not
  // a valid ASN1 OCTET STRING.
  // Returns ERROR if the cert is not loaded or the extension_nid is not
  // recognised.
  // TODO(ekasper): consider registering known custom NIDS explicitly with the
  // Cert API for safety.
  Status OctetStringExtensionData(int extension_nid,
                                  std::string* result) const;

  // Tests whether the certificate correctly follows the RFC rules for
  // using wildcard redaction.
  Cert::Status IsValidWildcardRedaction() const;
  // Tests if a certificate correctly follows the rules for name constrained
  // intermediate CA
  Cert::Status IsValidNameConstrainedIntermediateCa() const;

  // CertChecker needs access to the x509_ structure directly.
  friend class CertChecker;
  friend class TbsCertificate;
  // Allow CtExtensions tests to poke around the private members
  // for convenience.
  FRIEND_TEST(CtExtensionsTest, TestSCTExtension);
  FRIEND_TEST(CtExtensionsTest, TestEmbeddedSCTExtension);
  FRIEND_TEST(CtExtensionsTest, TestPoisonExtension);
  FRIEND_TEST(CtExtensionsTest, TestPrecertSigning);

 private:
  Status ExtensionIndex(int extension_nid, int* extension_index) const;
  Status GetExtension(int extension_nid, X509_EXTENSION** ext) const;
  Status ExtensionStructure(int extension_nid, void** ext_struct) const;
  static std::string PrintName(X509_NAME* name);
  static std::string PrintTime(ASN1_TIME* when);
  static Status DerEncodedName(X509_NAME* name, std::string* result);
  X509* x509_;

  DISALLOW_COPY_AND_ASSIGN(Cert);
};

// A wrapper around X509_CINF for chopping at the TBS to CT-sign it or verify
// a CT signature. We construct a TBS for this rather than chopping at the full
// cert so that the X509 information OpenSSL caches doesn't get out of sync.
class TbsCertificate {
 public:
  // TODO(ekasper): add construction from PEM and DER as needed.
  explicit TbsCertificate(const Cert& cert);
  ~TbsCertificate();

  bool IsLoaded() const {
    return x509_ != NULL;
  }

  // Sets the DER-encoded TBS structure in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  Cert::Status DerEncoding(std::string* result) const;

  // Delete the matching extension, if present.
  // Returns TRUE if the extension was present and was deleted.
  // Returns FALSE if the extension was not present or occurred more than once.
  // If multiple extensions with this NID are present, deletes the first
  // occurrence but returns FALSE.
  // Returns ERROR if the cert is not loaded, the NID is not recognised
  // or deletion failed internally.
  Cert::Status DeleteExtension(int extension_nid);

  // Copy the issuer and Authority KeyID information.
  // Requires that if Authority KeyID is present in the destination,
  // it must also be present in the source certificate.
  // Does not overwrite the critical bit.
  // Returns TRUE if the operation succeeded.
  // Returns FALSE if the operation could not be completed successfully.
  // Returns ERROR if either cert is not loaded.
  // Caller should not assume the cert was left unmodified upon FALSE as some
  // fields may have been copied successfully before an error occurred.
  Cert::Status CopyIssuerFrom(const Cert& from);

 private:
  Cert::Status ExtensionIndex(int extension_nid, int* extension_index) const;
  // OpenSSL does not expose a TBSCertificate API, so we keep the TBS wrapped
  // in the X509.
  X509* x509_;

  DISALLOW_COPY_AND_ASSIGN(TbsCertificate);
};

class CertChain {
 public:
  CertChain() = default;

  // Loads a chain of PEM-encoded certificates. If any of the PEM-strings
  // in the chain are invalid, clears the entire chain.
  // Caller should check IsLoaded() before doing anything else apart from
  // AddCert().
  explicit CertChain(const std::string& pem_string);
  ~CertChain();

  // Takes ownership of the cert.
  // If the cert has a valid X509 structure, adds it to the end of the chain
  // and returns TRUE.
  // Else returns ERROR.
  Cert::Status AddCert(Cert* cert);

  // Remove a cert from the end of the chain.
  // If successful, returns TRUE.
  // If the chain is empty, returns ERROR.
  Cert::Status RemoveCert();

  // Keep the first self-signed, remove the rest. We keep the first one so that
  // chains consisting only of a self-signed cert don't become invalid.
  // If successful, returns TRUE.
  // If the chain is empty, returns ERROR.
  // If the chain has no self-signed certs, does nothing and also returns TRUE.
  Cert::Status RemoveCertsAfterFirstSelfSigned();

  // True if the chain loaded correctly, and contains at least one valid cert.
  bool IsLoaded() const {
    return !chain_.empty();
  }

  size_t Length() const {
    return chain_.size();
  }

  Cert const* LeafCert() const {
    if (!IsLoaded())
      return NULL;
    return chain_.front();
  }

  Cert const* CertAt(size_t position) const {
    return chain_.size() <= position ? NULL : chain_[position];
  }

  Cert const* LastCert() const {
    if (!IsLoaded())
      return NULL;
    return chain_.back();
  }

  // Returns TRUE if the issuer of each cert is the subject of the
  // next cert, and each issuer has BasicConstraints CA:true, except
  // the root cert which may not have CA:true to support old CA
  // certificates.
  // Returns FALSE if the above does not hold.
  // Returns ERROR if the chain is not loaded or some error occurred.
  Cert::Status IsValidCaIssuerChainMaybeLegacyRoot() const;

  // Returns TRUE if each cert is signed by the next cert in chain.
  // Returns FALSE if the above does not hold.
  // Returns ERROR if the chain is not loaded or some error occurred.
  // Does not check whether issuers have CA capabilities.
  Cert::Status IsValidSignatureChain() const;

 private:
  void ClearChain();
  std::vector<Cert*> chain_;

  DISALLOW_COPY_AND_ASSIGN(CertChain);
};

// Note: CT extensions must be loaded to use this class. See
// log/ct_extensions.h for LoadCtExtensions().
class PreCertChain : public CertChain {
 public:
  PreCertChain() = default;

  explicit PreCertChain(const std::string& pem_string)
      : CertChain(pem_string) {
  }

  // Some convenient aliases.
  // A pointer to the precert.
  Cert const* PreCert() const {
    return LeafCert();
  }

  // A pointer to the issuing cert, which is either the issuing CA cert,
  // or a special-purpose Precertificate Signing Certificate issued
  // directly by the CA cert.
  // Can be NULL if the precert is issued directly by a root CA.
  Cert const* PrecertIssuingCert() const {
    return Length() >= 2 ? CertAt(1) : NULL;
  }

  // Returns TRUE if the chain has length >=2 and
  // extendedKeyUsage=precertSigning can be detected in the leaf's issuer.
  // Returns FALSE if the above does not hold.
  // Returns ERROR if the chain is not loaded, CT extensions could not be
  // detected or some other unknown error occurred while parsing the
  // extensions.
  Cert::Status UsesPrecertSigningCertificate() const;

  // Returns TRUE if
  // (1) the leaf certificate contains the critical poison extension;
  // (2) if the leaf certificate issuing certificate is present and has the
  //     CT EKU, and the leaf certificate has an Authority KeyID extension,
  //     then its issuing certificate also has this extension.
  // (2) is necessary for the log to be able to "predict" the AKID of the final
  // TbsCertificate.
  // Returns FALSE if the above does not hold.
  // Returns ERROR if the chain is not loaded, CT extensions could not be
  // detected or some other unknown error occurred while parsing the
  // extensions.
  // This method does not verify any signatures, or otherwise check
  // that the chain is valid.
  Cert::Status IsWellFormed() const;
};

}  // namespace cert_trans
#endif
