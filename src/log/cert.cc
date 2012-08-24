#include <assert.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>
#include <vector>

#include "cert.h"
#include "types.h"

const char Cert::kProofExtensionOID[] = "1.2.3.0";
const char Cert::kEmbeddedProofExtensionOID[] = "1.2.3.1";
const char Cert::kPoisonExtensionOID[] = "1.2.3.2";
const char Cert::kCtExtendedKeyUsageOID[] = "1.2.3.4";

//static
ASN1_OBJECT *Cert::ExtensionObject(const std::string oid) {
  unsigned char obj_buf[100];
  int obj_len = a2d_ASN1_OBJECT(obj_buf, sizeof obj_buf, oid.data(),
                                oid.length());
  assert(obj_len > 0);
  ASN1_OBJECT *obj = ASN1_OBJECT_create(0, obj_buf, obj_len, NULL, NULL);
  return obj;
}

Cert::Cert(X509 *x509) : x509_(X509_dup(x509)) {}

Cert::Cert(const std::string &pem_string) : x509_(NULL) {
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
  assert(clone != NULL);
  return clone;
}

bool Cert::HasExtension(const std::string &extension_oid) const {
  return ExtensionIndex(extension_oid) != -1;
}

bool Cert::HasExtension(int extension_nid) const {
  return ExtensionIndex(extension_nid) != -1;
}

bool Cert::IsCriticalExtension(const std::string &extension_oid) const {
  X509_EXTENSION *ext = GetExtension(extension_oid);
  assert (ext != NULL);
  return X509_EXTENSION_get_critical(ext);
}

bstring Cert::ExtensionData(const std::string &extension_oid) const {
  X509_EXTENSION *ext = GetExtension(extension_oid);
  // Always check if the extension exists first.
  assert(ext != NULL);
  ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
  return bstring(reinterpret_cast<byte*>(ext_data->data), ext_data->length);
}

bool Cert::HasBasicConstraintCA() const {
  assert(IsLoaded());
  BASIC_CONSTRAINTS *constraints = static_cast<BASIC_CONSTRAINTS*>(
      X509_get_ext_d2i(x509_, NID_basic_constraints, NULL, NULL));
  if (constraints == NULL)
    return false;
  bool is_ca = constraints->ca;
  BASIC_CONSTRAINTS_free(constraints);
  return is_ca;
}

bool Cert::HasExtendedKeyUsage(const std::string &key_usage_oid) const {
  EXTENDED_KEY_USAGE *eku = static_cast<EXTENDED_KEY_USAGE*>(
      X509_get_ext_d2i(x509_, NID_ext_key_usage, NULL, NULL));
  if (eku == NULL)
    return false;

  BIO *buf = BIO_new(BIO_s_mem());
  assert(buf != NULL);
  bool ext_key_usage_found = false;
  for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
    (void)BIO_reset(buf);
    int ret = i2a_ASN1_OBJECT(buf, sk_ASN1_OBJECT_value(eku, i));
    assert(ret > 0);
    ret = BIO_write(buf, "", 1); // NULL-terminate
    assert(ret == 1);
    char *oid;
    BIO_get_mem_data(buf, &oid);
    if (oid == key_usage_oid) {
      ext_key_usage_found = true;
      break;
    }
  }

  BIO_free(buf);
  EXTENDED_KEY_USAGE_free(eku);
  return ext_key_usage_found;
}

bool Cert::IsIssuedBy(const Cert &issuer) const {
  assert(IsLoaded());
  assert(issuer.IsLoaded());
  return X509_check_issued(const_cast<X509*>(issuer.x509_), x509_) == X509_V_OK;
}

bool Cert::IsSignedBy(const Cert &issuer) const {
  assert(IsLoaded());
  assert(issuer.IsLoaded());
  EVP_PKEY *issuer_key = X509_get_pubkey(issuer.x509_);
  if (issuer_key == NULL)
    return false;
  int ret = X509_verify(x509_, issuer_key);
  EVP_PKEY_free(issuer_key);
  return ret > 0;
}

bstring Cert::DerEncoding() const {
  assert(IsLoaded());
  unsigned char *der_buf = NULL;
  int der_length = i2d_X509(x509_, &der_buf);
  assert(der_length > 0);
  bstring ret(reinterpret_cast<byte*>(der_buf), der_length);
  OPENSSL_free(der_buf);
  return ret;
}

// WARNING WARNING this method modifies the x509_ structure
// and thus invalidates the cert. Use with care.
void Cert::DeleteExtension(const std::string &extension_oid) {
  assert(IsLoaded());
  int extension_index = ExtensionIndex(extension_oid);
  if (extension_index == -1)
    return;
  X509_EXTENSION *ext = X509_delete_ext(x509_, extension_index);
  // X509_delete_ext does not free the extension (GAH!), so we need to
  // free separately.
  assert(ext != NULL);
  X509_EXTENSION_free(ext);
  assert(!HasExtension(extension_oid));

  // Let OpenSSL know that it needs to re_encode.
  x509_->cert_info->enc.modified = 1;
}

// WARNING WARNING this method modifies the x509_ structure
// and thus invalidates the cert. Use with care.
void Cert::DeleteExtension(int extension_nid) {
  assert(IsLoaded());
  int extension_index = ExtensionIndex(extension_nid);
  if (extension_index == -1)
    return;
  X509_EXTENSION *ext = X509_delete_ext(x509_, extension_index);
  // X509_delete_ext does not free the extension (GAH!), so we need to
  // free separately.
  assert(ext != NULL);
  X509_EXTENSION_free(ext);
  assert(!HasExtension(extension_nid));

  // Let OpenSSL know that it needs to re_encode.
  x509_->cert_info->enc.modified = 1;
}

// WARNING WARNING this method modifies the x509_ structure
// and thus invalidates the cert. Use with care.
void Cert::DeleteSignature() {
  assert(IsLoaded());
  if (x509_->sig_alg != NULL) {
    X509_ALGOR_free(x509_->sig_alg);
    x509_->sig_alg = X509_ALGOR_new();
  }
  if (x509_->signature != NULL) {
    ASN1_BIT_STRING_free(x509_->signature);
    x509_->signature = ASN1_BIT_STRING_new();
  }

  x509_->cert_info->enc.modified = 1;
}

// WARNING WARNING this method modifies the x509_ structure
// and thus invalidates the cert. Use with care.
void Cert::CopyIssuerFrom(const Cert &from) {
  assert(IsLoaded());
  assert(from.IsLoaded());
  X509_NAME *ca_name = X509_get_issuer_name(from.x509_);
  assert(ca_name != NULL);
  X509_set_issuer_name(x509_, ca_name);

  // Fix the authority key extension, if it exists.
  X509_EXTENSION *from_ext = from.GetExtension(NID_authority_key_identifier);
  // If the source does not have an authority KeyID extension,
  // also delete it from the destination.
  if (from_ext == NULL) {
    DeleteExtension(NID_authority_key_identifier);
    return;
  }

  // If the destination does not have an authority KeyID extension,
  // add it as a last extension to the destination.
  int ret;
  X509_EXTENSION *to_ext = GetExtension(NID_authority_key_identifier);
  if (to_ext == NULL) {
    to_ext = X509_EXTENSION_create_by_NID(NULL, NID_authority_key_identifier,
                                          0, NULL);
    assert(to_ext != NULL);
    ret = X509_add_ext(x509_, to_ext, -1);
    assert(ret == 1);

    // X509_add_ext makes a copy, so find out its address.
    X509_EXTENSION_free(to_ext);
    to_ext = GetExtension(NID_authority_key_identifier);
  }

  // Copy the critical bit.
  ret = X509_EXTENSION_set_critical(to_ext,
                                    X509_EXTENSION_get_critical(from_ext));
  assert(ret == 1);
  // Copy data.
  ret = X509_EXTENSION_set_data(to_ext, X509_EXTENSION_get_data(from_ext));
  assert(ret == 1);

  x509_->cert_info->enc.modified = 1;
}

int Cert::ExtensionIndex(const std::string &extension_oid) const {
  assert(IsLoaded());
  ASN1_OBJECT *obj = ExtensionObject(extension_oid);
  assert(obj != NULL);
  int extension_index = X509_get_ext_by_OBJ(x509_, obj, -1);
  ASN1_OBJECT_free(obj);
  return extension_index;
}

int Cert::ExtensionIndex(int extension_nid) const {
  assert(IsLoaded());
  return X509_get_ext_by_NID(x509_, extension_nid, -1);
}

X509_EXTENSION *Cert::GetExtension(const std::string &extension_oid) const {
  assert(IsLoaded());
  int extension_index = ExtensionIndex(extension_oid);
  if (extension_index == -1)
    return NULL;
  return X509_get_ext(x509_, extension_index);
}

X509_EXTENSION *Cert::GetExtension(int extension_nid) const {
  assert(IsLoaded());
  int extension_index = ExtensionIndex(extension_nid);
  if (extension_index == -1)
    return NULL;
  return X509_get_ext(x509_, extension_index);
}

CertChain::CertChain(const std::string &pem_string) {
  // A read-only BIO.
  BIO *bio_in = BIO_new_mem_buf(const_cast<char*>(pem_string.data()),
                                pem_string.length());
  assert(bio_in != NULL);
  X509 *x509 = NULL;
  while ((x509 = PEM_read_bio_X509(bio_in, NULL, NULL, NULL)) != NULL) {
    Cert *cert = new Cert(x509);
    // Cert does not take ownership.
    X509_free(x509);
    assert(cert->IsLoaded());
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
  assert(cert != NULL);
  assert(cert->IsLoaded());

  chain_.push_back(cert);
}

void CertChain::RemoveCert() {
  assert(IsLoaded());
  delete chain_.back();
  chain_.pop_back();
}

CertChain::~CertChain() {
  ClearChain();
}

bool CertChain::IsValidIssuerChain() const {
  assert(IsLoaded());
  for (std::vector<Cert*>::const_iterator it = chain_.begin();
       it + 1 < chain_.end(); ++it) {
    Cert *subject = *it;
    Cert *issuer = *(it + 1);
    if (!subject->IsIssuedBy(*issuer))
    return false;
  }
  return true;
}

bool CertChain::IsValidSignatureChain() const {
  assert(IsLoaded());
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

bool PreCertChain::IsWellFormed() const {
  assert(IsLoaded());
  // We must have at least a leaf certificate and an issuing certificate.
  if (Length() < 2)
    return false;

  const Cert *pre = PreCert();
  assert(pre != NULL);

  // First, check that the leaf contains the critical poison extension.
  if (!pre->HasExtension(Cert::kPoisonExtensionOID) ||
      !pre->IsCriticalExtension(Cert::kPoisonExtensionOID))
    return false;

  // The next cert should be the issuing precert.
  // Check that it is CA:FALSE, and contains the desired Extended Key Usage.
  const Cert *pre_ca = CaPreCert();
  assert(pre_ca != NULL);

  // Check that pre is issued by pre_ca.
  if (!pre->IsIssuedBy(*pre_ca))
    return false;

  if (!pre_ca->HasExtension(NID_basic_constraints) ||
      pre_ca->HasBasicConstraintCA() ||
      !pre_ca->HasExtendedKeyUsage(Cert::kCtExtendedKeyUsageOID))
    return false;

  // Check that both certs have an Authority KeyID extension.
  return pre->HasExtension(NID_authority_key_identifier) &&
      pre_ca->HasExtension(NID_authority_key_identifier);
}
