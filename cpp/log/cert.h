#ifndef CERT_TRANS_LOG_CERT_H_
#define CERT_TRANS_LOG_CERT_H_

#include <gtest/gtest_prod.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <memory>
#include <string>
#include <vector>

#include "base/macros.h"
#include "util/openssl_scoped_types.h"
#include "util/statusor.h"

namespace cert_trans {

// Tests if a hostname contains any redactions ('?' elements). If it does
// not then there is no need to apply the validation below
bool IsRedactedHost(const std::string& hostname);
// Tests if a hostname containing any redactions follows the RFC rules
bool IsValidRedactedHost(const std::string& hostname);

class Cert {
 public:
  // The following factory static methods return null if the input is
  // not valid.
  static std::unique_ptr<Cert> FromDerString(const std::string& der_string);
  // Caller still owns the BIO afterwards.
  static std::unique_ptr<Cert> FromDerBio(BIO* bio_in);
  static std::unique_ptr<Cert> FromPemString(const std::string& pem_string);
  // Will return null if |x509| is null.
  static std::unique_ptr<Cert> FromX509(ScopedX509 x509);

  // Returns null if there was a problem with the underlying copy.
  std::unique_ptr<Cert> Clone() const;

  // These just return an empty string if an error occurs.
  std::string PrintVersion() const;
  std::string PrintSerialNumber() const;
  std::string PrintIssuerName() const;
  std::string PrintSubjectName() const;
  std::string PrintNotBefore() const;
  std::string PrintNotAfter() const;
  std::string PrintSignatureAlgorithm() const;

  bool IsIdenticalTo(const Cert& other) const;

  // Returns TRUE if the extension is present.
  // Returns FALSE if the extension is not present.
  // Returns ERROR if the cert is not loaded, extension_nid is not recognised
  // or some other unknown error occurred while parsing the extensions.
  // NID must be either an OpenSSL built-in NID, or one registered by the user
  // with OBJ_create. (See log/ct_extensions.h for sample code.)
  util::StatusOr<bool> HasExtension(int extension_nid) const;

  // Returns TRUE if the extension is present and critical.
  // Returns FALSE if the extension is not present, or is present but not
  // critical.
  // Returns ERROR if the cert is not loaded, extension_nid is not recognised
  // or some other unknown error occurred while parsing the extensions.
  // NID must be either an OpenSSL built-in NID, or one registered by the user
  // with OBJ_create. (See log/ct_extensions.h for sample code.)
  util::StatusOr<bool> HasCriticalExtension(int extension_nid) const;

  // Returns TRUE if the basicConstraints extension is present and CA=TRUE.
  // Returns FALSE if the extension is not present, is present but CA=FALSE,
  // or is present but could not be decoded.
  // Returns ERROR if the cert is not loaded or some other unknown error
  // occurred while parsing the extensions.
  util::StatusOr<bool> HasBasicConstraintCATrue() const;

  // Returns TRUE if extendedKeyUsage extension is present and the specified
  // key usage is set.
  // Returns FALSE if the extension is not present, is present but could not
  // be decoded, or is present but the specified key usage is not set.
  // Returns ERROR if the cert is not loaded, extension_nid is not recognised
  // or some other unknown error occurred while parsing the extensions.
  // NID must be either an OpenSSL built-in NID, or one registered by the user
  // with OBJ_create. (See log/ct_extensions.h for sample code.)
  util::StatusOr<bool> HasExtendedKeyUsage(int key_usage_nid) const;

  // Returns TRUE if the Cert's issuer matches |issuer|.
  // Returns FALSE if there is no match.
  // Returns ERROR if either cert is not loaded.
  util::StatusOr<bool> IsIssuedBy(const Cert& issuer) const;

  // Returns TRUE if the cert's signature can be verified by the issuer's
  // public key.
  // Returns FALSE if the signature cannot be verified.
  // Returns ERROR if either cert is not loaded or some other error occurs.
  // Does not check if issuer has CA capabilities.
  util::StatusOr<bool> IsSignedBy(const Cert& issuer) const;

  util::StatusOr<bool> IsSelfSigned() const {
    return IsIssuedBy(*this);
  }

  // Sets the DER encoding of the cert in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  util::Status DerEncoding(std::string* result) const;

  // Sets the PEM encoding of the cert in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  util::Status PemEncoding(std::string* result) const;

  // Sets the SHA256 digest of the cert in |result|.
  // Returns TRUE if computing the digest succeeded.
  // Returns FALSE if computing the digest failed.
  // Returns ERROR if the cert is not loaded.
  util::Status Sha256Digest(std::string* result) const;

  // Sets the DER-encoded TBS component of the cert in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  util::Status DerEncodedTbsCertificate(std::string* result) const;

  // Sets the DER-encoded subject Name component of the cert in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  util::Status DerEncodedSubjectName(std::string* result) const;

  // Sets the DER-encoded issuer Name component of the cert in |result|.
  // Returns TRUE if the encoding succeeded.
  // Returns FALSE if the encoding failed.
  // Returns ERROR if the cert is not loaded.
  util::Status DerEncodedIssuerName(std::string* result) const;

  // Sets the SHA256 digest of the cert's public key in |result|.
  // Returns TRUE if computing the digest succeeded.
  // Returns FALSE if computing the digest failed.
  // Returns ERROR if the cert is not loaded.
  util::Status PublicKeySha256Digest(std::string* result) const;

  // Sets the Subject Alternative Name dNSNames in |dns_alt_names|.
  // Returns Status::OK if the SAN dNSNames were extracted.
  // Returns INVALID_ARGUMENT if the DAN dNSNames could not be extracted.
  // Returns FAILED_PRECONDITION if the cert is not loaded.
  util::Status SubjectAltNames(std::vector<std::string>* dns_alt_names) const;

  // Sets the SHA256 digest of the cert's subjectPublicKeyInfo in |result|.
  // Returns TRUE if computing the digest succeeded.
  // Returns FALSE if computing the digest failed.
  // Returns ERROR if the cert is not loaded.
  util::Status SPKISha256Digest(std::string* result) const;

  // Get the cert's subjectPublicKeyInfo.
  // Returns error INVALID_ARGUMENT if parsing the cert DER failed.
  // Returns error FAILED_PRECONDITION if the cert is not loaded.
  util::StatusOr<std::string> SPKI() const;

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
  // Returns OK if the extension data could be fetched and decoded.
  // Returns NOT_FOUND if the extension is not present, or is present but is
  // not a valid ASN1 OCTET STRING.
  // Returns a suitable status if the cert is not loaded or the extension_nid
  // is not recognised.
  // TODO(ekasper): consider registering known custom NIDS explicitly with the
  // Cert API for safety.
  util::Status OctetStringExtensionData(int extension_nid,
                                        std::string* result) const;

  // Tests whether the certificate correctly follows the RFC rules for
  // using wildcard redaction.
  util::Status IsValidWildcardRedaction() const;
  // Tests if a certificate correctly follows the rules for name constrained
  // intermediate CA
  util::Status IsValidNameConstrainedIntermediateCa() const;

  // CertChecker needs access to the x509_ structure directly.
  friend class CertChecker;
  // CmsVerifier needs access to the x509_ structure directly.
  friend class CmsVerifier;
  friend class TbsCertificate;
  // Allow CtExtensions tests to poke around the private members
  // for convenience.
  FRIEND_TEST(CtExtensionsTest, TestSCTExtension);
  FRIEND_TEST(CtExtensionsTest, TestEmbeddedSCTExtension);
  FRIEND_TEST(CtExtensionsTest, TestPoisonExtension);
  FRIEND_TEST(CtExtensionsTest, TestPrecertSigning);

 private:
  // Will CHECK-fail if |x509| is null.
  explicit Cert(ScopedX509 x509);
  Cert() = delete;

  util::StatusOr<int> ExtensionIndex(int extension_nid) const;
  util::StatusOr<X509_EXTENSION*> GetExtension(int extension_nid) const;
  util::StatusOr<void*> ExtensionStructure(int extension_nid) const;
  bool ValidateRedactionSubjectAltNameAndCN(int* dns_alt_name_count,
                                            util::Status* status) const;
  util::StatusOr<bool> LogUnsupportedAlgorithm() const;
  static std::string PrintName(X509_NAME* name);
  static std::string PrintTime(ASN1_TIME* when);
  static util::Status DerEncodedName(X509_NAME* name, std::string* result);
  const ScopedX509 x509_;

  DISALLOW_COPY_AND_ASSIGN(Cert);
};

// A wrapper around X509_CINF for chopping at the TBS to CT-sign it or verify
// a CT signature. We construct a TBS for this rather than chopping at the full
// cert so that the X509 information OpenSSL caches doesn't get out of sync.
class TbsCertificate {
 public:
  // TODO(ekasper): add construction from PEM and DER as needed.
  explicit TbsCertificate(const Cert& cert);

  bool IsLoaded() const {
    return x509_ != NULL;
  }

  // Sets the DER-encoded TBS structure in |result|.
  // Returns OK if the encoding succeeded.
  // Returns a suitable eror status if the encoding failed.
  // Returns FAILED_PRECONDITION if the cert is not loaded.
  util::Status DerEncoding(std::string* result) const;

  // Delete the matching extension, if present.
  // Returns OK if the extension was present and was deleted.
  // Returns NOT_FOUND if the extension was not present.
  // If multiple extensions with this NID are present, deletes the first
  // occurrence but returns ALREADY_EXISTS.
  // Returns a suitable status if the cert is not loaded, the NID is not
  // recognised or deletion failed internally.
  util::Status DeleteExtension(int extension_nid);

  // Copy the issuer and Authority KeyID information.
  // Requires that if Authority KeyID is present in the destination,
  // it must also be present in the source certificate.
  // Does not overwrite the critical bit.
  // Returns OK if the operation succeeded.
  // Returns a suitable status if the operation could not be completed
  // successfully.
  // Returns FAILED_PRECONDITION if either cert is not loaded.
  // Caller should not assume the dest cert was left unmodified without OK as
  // fields may have been copied successfully before an error occurred.
  util::Status CopyIssuerFrom(const Cert& from);

 private:
  util::StatusOr<int> ExtensionIndex(int extension_nid) const;
  // OpenSSL does not expose a TBSCertificate API, so we keep the TBS wrapped
  // in the X509.
  ScopedX509 x509_;

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

  // If the cert has a valid X509 structure, adds it to the end of the chain
  // and returns true.
  // Else returns false.
  bool AddCert(std::unique_ptr<Cert> cert);

  // Remove a cert from the end of the chain, if there is one.
  void RemoveCert();

  // Keep the first self-signed, remove the rest. We keep the first one so that
  // chains consisting only of a self-signed cert don't become invalid.
  // If successful, returns true.
  // If the chain is empty, returns false.
  // If the chain has no self-signed certs, does nothing and also returns true.
  bool RemoveCertsAfterFirstSelfSigned();

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
    return chain_.front().get();
  }

  Cert const* CertAt(size_t position) const {
    return chain_.size() <= position ? NULL : chain_[position].get();
  }

  Cert const* LastCert() const {
    if (!IsLoaded())
      return NULL;
    return chain_.back().get();
  }

  // Returns TRUE if the issuer of each cert is the subject of the
  // next cert, and each issuer has BasicConstraints CA:true, except
  // the root cert which may not have CA:true to support old CA
  // certificates.
  // Returns FALSE if the above does not hold.
  // Returns ERROR if the chain is not loaded or some error occurred.
  util::Status IsValidCaIssuerChainMaybeLegacyRoot() const;

  // Is OK if each certificate is signed by the next certificate in
  // the chain. Does not check whether issuers have CA capabilities.
  util::Status IsValidSignatureChain() const;

 private:
  void ClearChain();
  std::vector<std::unique_ptr<Cert>> chain_;

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
  util::StatusOr<bool> UsesPrecertSigningCertificate() const;

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
  util::StatusOr<bool> IsWellFormed() const;
};

}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_CERT_H_
