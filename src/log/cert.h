#ifndef CERT_H
#define CERT_H

#include <gtest/gtest_prod.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <string>
#include <vector>

class Cert {
 public:
  // Makes a local copy of the X509 structure. It's advisable to check
  // IsLoaded() after construction to verify the copy operation succeeded.
  explicit Cert(X509 *x509);
  // May fail, but we don't want to die on invalid inputs,
  // so caller should check IsLoaded() before doing anything else.
  // All attempts to operate on an unloaded cert will fail with ERROR.
  explicit Cert(const std::string &pem_string);
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
  };

  bool IsLoaded() const { return x509_ != NULL; }

  // Check IsLoaded() after Clone to verify the underlying copy succeeded.
  Cert *Clone() const;

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
  Status IsIssuedBy(const Cert &issuer) const;

  // Returns TRUE if the cert's signature can be verified by the issuer's
  // public key.
  // Returns FALSE if the signature cannot be verified.
  // Returns ERROR if either cert is not loaded or some other error occurs.
  // Does not check if issuer has CA capabilities.
  Status IsSignedBy(const Cert &issuer) const;

  Status IsSelfSigned() const { return IsIssuedBy(*this); }

  // Sets the DER encoding of the cert in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  Status DerEncoding(std::string *result) const;

  // Sets the SHA256 digest of the cert in |result|.
  // Returns TRUE if computing the digest succeeded.
  // Returns FALSE if computing the digest failed.
  // Returns ERROR if the cert is not loaded.
  Status Sha256Digest(std::string *result) const;

  // Sets the DER-encoded TBS component of the cert in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  Status DerEncodedTbsCertificate(std::string *result) const;

  // Sets the SHA256 digest of the cert's public key in |result|.
  // Returns TRUE if computing the digest succeeded.
  // Returns FALSE if computing the digest failed.
  // Returns ERROR if the cert is not loaded.
  Status PublicKeySha256Digest(std::string *result) const;

  // Fetch data from an extension if encoded as an ASN1_OCTET_STRING.
  // Useful for handling custom extensions registered with X509V3_EXT_add.
  // Returns true if the extension is present and the data could be decoded.
  // Returns false if the extension is not present or the data is not a valid
  // ASN1_OCTET_STRING.
  // Caller is responsible for ensuring that the expected type
  // of the extension contents is an ASN1 OCTET STRING.
  // Only use if you think you know what you're doing.
  // Returns TRUE if the extension data could be fetched and decoded.
  // Returns FALSE if the extension is not present, or is present but is not
  // a valid ASN1 OCTET STRING.
  // Returns ERROR if the cert is not loaded, the extension_nid is not
  // recognised or the registered type of this extension is not an
  // ASN1 OCTET STRING.
  // TODO(ekasper): consider registering known custom NIDS explicitly with the
  // Cert API for safety.
  Status OctetStringExtensionData(int extension_nid,
                                  std::string *result) const;

  // WARNING WARNING The following methods modify the x509_ structure
  // and thus invalidate the cert.
  // They are mostly needed for processing precerts. Use with care.
  // Delete the matching extension, if present.
  // Returns TRUE if the extension was present and was deleted.
  // Returns FALSE if the extension was not present or occurred more than once.
  // If multiple extensions with this NID are present, deletes the first
  // occurrence but returns FALSE.
  // Returns ERROR if the cert is not loaded, the NID is not recognised
  // or deletion failed internally.
  Status DeleteExtension(int extension_nid);

  // Copy the issuer and Authority KeyID information.
  // Requires that if Authority KeyID is present in the destination,
  // it must also be present in the source certificate.
  // Does not overwrite the critical bit.
  // Returns TRUE if the operation succeeded.
  // Returns FALSE if the operation could not be completed successfully.
  // Returns ERROR if either cert is not loaded.
  // Caller should not assume the cert was left unmodified upon FALSE as some
  // fields may have been copied successfully before an error occurred.
  Status CopyIssuerFrom(const Cert &from);

  // CertChecker needs access to the x509_ structure directly.
  friend class CertChecker;
  // Allow CtExtensions tests to poke around the private members
  // for convenience.
  FRIEND_TEST(CtExtensionsTest, TestSCTExtension);
  FRIEND_TEST(CtExtensionsTest, TestEmbeddedSCTExtension);
  FRIEND_TEST(CtExtensionsTest, TestPoisonExtension);
  FRIEND_TEST(CtExtensionsTest, TestPrecertSigning);
 private:
  Status ExtensionIndex(int extension_nid, int *extension_index) const;
  Status GetExtension(int extension_nid, X509_EXTENSION **ext) const;
  Status ExtensionStructure(int extension_nid, void **ext_struct) const;

  X509 *x509_;
};

class CertChain {
 public:
  CertChain() {}
  // Loads a chain of PEM-encoded certificates. If any of the PEM-strings
  // in the chain are invalid, clears the entire chain.
  // Caller should check IsLoaded() before doing anything else apart from
  // AddCert().
  explicit CertChain(const std::string &pem_string);
  ~CertChain();

  // Takes ownership of the cert.
  // If the cert has a valid X509 structure, adds it to the end of the chain
  // and returns TRUE.
  // Else returns ERROR.
  Cert::Status AddCert(Cert *cert);

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
  bool IsLoaded() const { return !chain_.empty(); }

  size_t Length() const {
    return chain_.size();
  }

  Cert const *LeafCert() const {
    if (!IsLoaded())
      return NULL;
    return chain_.front();
  }

  Cert const *CertAt(size_t position) const {
    return chain_.size() <= position ? NULL : chain_[position];
  }

  Cert const *LastCert() const {
    if (!IsLoaded())
      return NULL;
    return chain_.back();
  }

  // Returns TRUE if the issuer of each cert is the subject of
  // the next cert, and each issuer has BasicConstraints CA:true.
  // Returns FALSE if the above does not hold.
  // Returns ERROR if the chain is not loaded or some error occurred.
  Cert::Status IsValidCaIssuerChain() const;

  // Returns TRUE if each cert is signed by the next cert in chain.
  // Returns FALSE if the above does not hold.
  // Returns ERROR if the chain is not loaded or some error occurred.
  // Does not check whether issuers have CA capabilities.
  Cert::Status IsValidSignatureChain() const;

 private:
  void ClearChain();
  std::vector<Cert*> chain_;
};

// Note: CT extensions must be loaded to use this class. See
// log/ct_extensions.h for LoadCtExtensions().
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

  // Returns TRUE if the chain has length >=2 and
  // extendedKeyUsage=precertSigning can be detected in the leaf's issuer.
  // Returns FALSE if the above does not hold.
  // Returns ERROR if the chain is not loaded, CT extensions could not be
  // detected or some other unknown error occurred while parsing the extensions.
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
  // detected or some other unknown error occurred while parsing the extensions.
  // This method does not verify any signatures, or otherwise check
  // that the chain is valid.
  Cert::Status IsWellFormed() const;
};
#endif
