#include <glog/logging.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>
#include <vector>

#include "log/cert.h"
#include "log/ct_extensions.h"

using std::string;

// TODO(ekasper): libify this code - remove most (over-zealous) CHECKs,
// improve logging, handle OpenSSL weirdness more gently.

Cert::Cert(X509 *x509) : x509_(X509_dup(x509)) {}

Cert::Cert(const string &pem_string) : x509_(NULL) {
  // A read-only bio.
  BIO *bio_in = BIO_new_mem_buf(const_cast<char*>(pem_string.data()),
                                pem_string.length());
  x509_ = PEM_read_bio_X509(bio_in, NULL, NULL, NULL);
  BIO_free(bio_in);
}

Cert::~Cert() {
  if (x509_ != NULL)
    X509_free(x509_);
}

Cert *Cert::Clone() const {
  Cert *clone = new Cert(x509_);
  return clone;
}

bool Cert::HasExtension(int extension_nid) const {
  return ExtensionIndex(extension_nid) != -1;
}

bool Cert::IsCriticalExtension(int extension_nid) const {
  return IsCriticalExtension(GetExtension(extension_nid));
}

bool Cert::OctetStringExtensionData(int extension_nid,
                                    string *result) const {
  X509_EXTENSION *ext = GetExtension(extension_nid);
  // You should have checked already...
  if (ext == NULL) {
    LOG(ERROR) << "Certificate does not have an extension with nid "
               << extension_nid;
    return false;
  }

  ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
  if (ext_data == NULL) {
    LOG(ERROR) << "NULL extension data";
    return false;
  }

  const unsigned char *ptr = ext_data->data;
  ASN1_OCTET_STRING *octet = d2i_ASN1_OCTET_STRING(NULL, &ptr,
                                                   ext_data->length);

  if (octet == NULL) {
    LOG(ERROR) << "Extension data is not a valid ASN1 octet string";
    return false;
  }
  result->assign(string(reinterpret_cast<const char*>(octet->data),
                        octet->length));
  ASN1_OCTET_STRING_free(octet);
  return true;
}

bool Cert::HasBasicConstraintCA() const {
  CHECK(IsLoaded());
  BASIC_CONSTRAINTS *constraints = static_cast<BASIC_CONSTRAINTS*>(
      X509_get_ext_d2i(x509_, NID_basic_constraints, NULL, NULL));
  if (constraints == NULL)
    return false;
  bool is_ca = constraints->ca;
  BASIC_CONSTRAINTS_free(constraints);
  return is_ca;
}

bool Cert::HasExtendedKeyUsage(int key_usage_nid) const {
  EXTENDED_KEY_USAGE *eku = static_cast<EXTENDED_KEY_USAGE*>(
      X509_get_ext_d2i(x509_, NID_ext_key_usage, NULL, NULL));
  if (eku == NULL)
    return false;

  bool ext_key_usage_found = false;
  for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
    if (OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i)) == key_usage_nid) {
      ext_key_usage_found = true;
      break;
    }
  }

  EXTENDED_KEY_USAGE_free(eku);
  return ext_key_usage_found;
}

bool Cert::IsIssuedBy(const Cert &issuer) const {
  CHECK(IsLoaded());
  CHECK(issuer.IsLoaded());
  return X509_check_issued(const_cast<X509*>(issuer.x509_), x509_) == X509_V_OK;
}

bool Cert::IsSignedBy(const Cert &issuer) const {
  CHECK(IsLoaded());
  CHECK(issuer.IsLoaded());
  EVP_PKEY *issuer_key = X509_get_pubkey(issuer.x509_);
  if (issuer_key == NULL)
    return false;
  int ret = X509_verify(x509_, issuer_key);
  EVP_PKEY_free(issuer_key);
  return ret > 0;
}

string Cert::DerEncoding() const {
  CHECK(IsLoaded());
  unsigned char *der_buf = NULL;
  int der_length = i2d_X509(x509_, &der_buf);
  CHECK_GT(der_length, 0);
  string ret(reinterpret_cast<char*>(der_buf), der_length);
  OPENSSL_free(der_buf);
  return ret;
}

string Cert::Sha256Digest() const {
  CHECK(IsLoaded());
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int len;
  CHECK_EQ(1, X509_digest(x509_, EVP_sha256(), digest, &len));
  return string(reinterpret_cast<char*>(digest), len);
}

string Cert::DerEncodedTbsCertificate() const {
  CHECK(IsLoaded());
  unsigned char *der_buf = NULL;
  // There appears to be no "clean" way for getting the TBS out.
  int der_length = i2d_X509_CINF(x509_->cert_info, &der_buf);
  CHECK_GT(der_length, 0);
  string ret(reinterpret_cast<char*>(der_buf), der_length);
  OPENSSL_free(der_buf);
  return ret;
}

string Cert::PublicKeySha256Digest() const {
  CHECK(IsLoaded());
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int len;
  CHECK_EQ(1, X509_pubkey_digest(x509_, EVP_sha256(), digest, &len));
  return string(reinterpret_cast<char*>(digest), len);
}

// WARNING WARNING this method modifies the x509_ structure
// and thus invalidates the cert. Use with care.
void Cert::DeleteExtension(int extension_nid) {
  CHECK(IsLoaded());
  int extension_index = ExtensionIndex(extension_nid);
  if (extension_index == -1)
    return;
  X509_EXTENSION *ext = X509_delete_ext(x509_, extension_index);
  // X509_delete_ext does not free the extension (GAH!), so we need to
  // free separately.
  CHECK_NOTNULL(ext);
  X509_EXTENSION_free(ext);
  CHECK(!HasExtension(extension_nid));

  // Let OpenSSL know that it needs to re_encode.
  x509_->cert_info->enc.modified = 1;
}

// WARNING WARNING this method modifies the x509_ structure
// and thus invalidates the cert. Use with care.
bool Cert::CopyIssuerFrom(const Cert &from) {
  CHECK(IsLoaded());
  CHECK(from.IsLoaded());
  X509_NAME *ca_name = X509_get_issuer_name(from.x509_);
  CHECK_NOTNULL(ca_name);
  X509_set_issuer_name(x509_, ca_name);

  X509_EXTENSION *to_ext = GetExtension(NID_authority_key_identifier);

  // If the destination does not have the extension, do nothing.
  if (to_ext == NULL)
    return true;

  X509_EXTENSION *from_ext = from.GetExtension(NID_authority_key_identifier);

  // If the source does not have the extension, we can't copy.
  if (from_ext == NULL)
    return false;

  // Both have the extension set.
  // Technically, this extension should never be critical, but this check is
  // done elsewhere. Here we just check that the bit matches - else we don't
  // really know whether we should copy or keep it.
  if (IsCriticalExtension(from_ext) != IsCriticalExtension(to_ext))
    return false;

  // Copy data.
  CHECK_EQ(1,
           X509_EXTENSION_set_data(to_ext, X509_EXTENSION_get_data(from_ext)));

  x509_->cert_info->enc.modified = 1;

  return true;
}

int Cert::ExtensionIndex(int extension_nid) const {
  CHECK(IsLoaded());
  return X509_get_ext_by_NID(x509_, extension_nid, -1);
}

X509_EXTENSION *Cert::GetExtension(int extension_nid) const {
  CHECK(IsLoaded());
  int extension_index = ExtensionIndex(extension_nid);
  if (extension_index == -1)
    return NULL;
  return X509_get_ext(x509_, extension_index);
}

// static
bool Cert::IsCriticalExtension(X509_EXTENSION *ext) {
  CHECK_NOTNULL(ext);
  return X509_EXTENSION_get_critical(ext);
}

CertChain::CertChain(const string &pem_string) {
  // A read-only BIO.
  BIO *bio_in = BIO_new_mem_buf(const_cast<char*>(pem_string.data()),
                                pem_string.length());
  CHECK_NOTNULL(bio_in);
  X509 *x509 = NULL;
  while ((x509 = PEM_read_bio_X509(bio_in, NULL, NULL, NULL)) != NULL) {
    Cert *cert = new Cert(x509);
    // Cert does not take ownership.
    X509_free(x509);
    CHECK(cert->IsLoaded());
    chain_.push_back(cert);
  }

  BIO_free(bio_in);

  // The last error must be EOF.
  unsigned long err = ERR_peek_last_error();
  if (ERR_GET_LIB(err) != ERR_LIB_PEM ||
      ERR_GET_REASON(err) != PEM_R_NO_START_LINE) {
    // A real error.
    ClearChain();
  } else {
    ERR_clear_error();
  }
}

void CertChain::AddCert(Cert *cert) {
  CHECK_NOTNULL(cert);
  CHECK(cert->IsLoaded());

  chain_.push_back(cert);
}

void CertChain::RemoveCert() {
  CHECK(IsLoaded());
  delete chain_.back();
  chain_.pop_back();
}

void CertChain::RemoveCertsAfterFirstSelfSigned() {
  CHECK(IsLoaded());
  int first_self_signed = chain_.size();

  // Fidn the first self-signed certificate.
  for (size_t i = 0; i < chain_.size(); ++i) {
    if (chain_[i]->IsSelfSigned()) {
      first_self_signed = i;
      break;
    }
  }

  // Remove everything after it.
  int chain_size = chain_.size();
  for (int i = first_self_signed + 1; i < chain_size; ++i) {
    chain_.pop_back();
  }
}


CertChain::~CertChain() {
  ClearChain();
}

bool CertChain::IsValidCaIssuerChain() const {
  CHECK(IsLoaded());
  for (std::vector<Cert*>::const_iterator it = chain_.begin();
       it + 1 < chain_.end(); ++it) {
    Cert *subject = *it;
    Cert *issuer = *(it + 1);
    if (!issuer->HasBasicConstraintCA() || !subject->IsIssuedBy(*issuer))
      return false;
  }
  return true;
}

bool CertChain::IsValidSignatureChain() const {
  CHECK(IsLoaded());
  for (std::vector<Cert*>::const_iterator it = chain_.begin();
       it + 1 < chain_.end(); ++it) {
    Cert *subject = *it;
    Cert *issuer = *(it + 1);
    if (!subject->IsSignedBy(*issuer))
    return false;
  }
  return true;
}

void CertChain::ClearChain() {
  std::vector<Cert*>::const_iterator it;
  for (it = chain_.begin(); it < chain_.end(); ++it)
    delete *it;
  chain_.clear();
}

bool PreCertChain::UsesPrecertSigningCertificate() const {
  const Cert *issuer = PrecertIssuingCert();
  if (issuer == NULL) {
    // No issuer, so it must be a real root CA from the store.
    return false;
  }

  CHECK(issuer->IsLoaded());
  return issuer->HasExtendedKeyUsage(ct::NID_ctPrecertificateSigning);
}

bool PreCertChain::IsWellFormed() const {
  CHECK(IsLoaded());

  const Cert *pre = PreCert();
  CHECK_NOTNULL(pre);

  // (1) Check that the leaf contains the critical poison extension.
  if (!pre->HasExtension(ct::NID_ctPoison) ||
      !pre->IsCriticalExtension(ct::NID_ctPoison))
    return false;

  if (!UsesPrecertSigningCertificate()) {
    // No more checks
    return true;
  }

  const Cert *issuer = PrecertIssuingCert();
  // (2) Check that the AKID profiles allow copying of the correct issuer.
  // If pre has the extension set but the issuer doesn't, error.
  if (pre->HasExtension(NID_authority_key_identifier) &&
      !issuer->HasExtension(NID_authority_key_identifier))
    return false;

  // It is an error to set the critical bit for this extension.
  // We do not generally check that extensions are validly formed but we do
  // check for this one as we'll be using it to form the TBS entry.
  if (pre->HasExtension(NID_authority_key_identifier) &&
      (pre->IsCriticalExtension(NID_authority_key_identifier) ||
       issuer->IsCriticalExtension(NID_authority_key_identifier)))
    return false;

  return true;
}
