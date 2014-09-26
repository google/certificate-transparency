/* -*- indent-tabs-mode: nil -*- */
#include "log/cert.h"

#include <boost/shared_ptr.hpp>
#include <glog/logging.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>
#include <time.h>
#include <vector>

#include "log/ct_extensions.h"
#include "merkletree/serial_hasher.h"
#include "util/openssl_util.h"  // For LOG_OPENSSL_ERRORS

using boost::shared_ptr;
using std::string;
using util::ClearOpenSSLErrors;

#if OPENSSL_VERSION_NUMBER < 0x10002000L
// Backport from 1.0.2-beta3.
static int i2d_re_X509_tbs(X509 *x, unsigned char **pp) {
  x->cert_info->enc.modified = 1;
  return i2d_X509_CINF(x->cert_info, pp);
}

static int X509_get_signature_nid(const X509 *x) {
  return OBJ_obj2nid(x->sig_alg->algorithm);
}
#endif

namespace ct {

Cert::Cert(X509 *x509) : x509_(x509) {
}

Cert::Cert(const std::string &pem_string)
    : x509_(NULL) {
  // A read-only bio.
  BIO *bio_in = BIO_new_mem_buf(const_cast<char*>(pem_string.data()),
                                pem_string.length());
  if (bio_in == NULL) {
    LOG_OPENSSL_ERRORS(ERROR);
    return;
  }

  x509_ = PEM_read_bio_X509(bio_in, NULL, NULL, NULL);
  BIO_free(bio_in);

  if (x509_ == NULL) {
    // At this point most likely the input was just corrupt. There are few
    // real errors that may have happened (a malloc failure is one) and it is
    // virtually impossible to fish them out.
    LOG(WARNING) << "Input is not a valid PEM-encoded certificate";
    LOG_OPENSSL_ERRORS(WARNING);
  }
}

Cert::~Cert() {
  if (x509_ != NULL)
    X509_free(x509_);
}

Cert *Cert::Clone() const {
  X509 *x509 = NULL;
  if (x509_ != NULL) {
    x509 = X509_dup(x509_);
    if (x509 == NULL)
      LOG_OPENSSL_ERRORS(ERROR);
  }
  Cert *clone = new Cert(x509);
  return clone;
}

Cert::Status Cert::LoadFromDerString(const std::string &der_string) {
  if (x509_ != NULL) {
    X509_free(x509_);
    x509_ = NULL;
  }
  const unsigned char *start =
      reinterpret_cast<const unsigned char*>(der_string.data());
  x509_ = d2i_X509(NULL, &start, der_string.size());
  if (x509_ == NULL) {
    LOG(WARNING) << "Input is not a valid DER-encoded certificate";
    LOG_OPENSSL_ERRORS(WARNING);
    return Cert::FALSE;
  }
  return Cert::TRUE;
}

string Cert::PrintIssuerName() const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return string();
  }

  return PrintName(X509_get_issuer_name(x509_));
}

string Cert::PrintSubjectName() const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return string();
  }

  return PrintName(X509_get_subject_name(x509_));
}

// static
string Cert::PrintName(X509_NAME *name) {
  if (name == NULL)
    return string();
  BIO *bio = BIO_new(BIO_s_mem());
  if (bio == NULL) {
    LOG_OPENSSL_ERRORS(ERROR);
    return string();
  }

  if (X509_NAME_print_ex(bio, name, 0, 0) != 1) {
    LOG_OPENSSL_ERRORS(ERROR);
    BIO_free(bio);
    return string();
  }

  string ret = util::ReadBIO(bio);
  BIO_free(bio);
  return ret;
}

string Cert::PrintNotBefore() const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return string();
  }

  return PrintTime(X509_get_notBefore(x509_));
}

string Cert::PrintNotAfter() const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return string();
  }

  return PrintTime(X509_get_notAfter(x509_));
}

string Cert::PrintSignatureAlgorithm() const {
  const char *sigalg = OBJ_nid2ln(X509_get_signature_nid(x509_));
  if (sigalg == NULL)
    return "NULL";
  return string(sigalg);
}

// static
string Cert::PrintTime(ASN1_TIME* when) {
  if (when == NULL)
    return string();

  BIO *bio = BIO_new(BIO_s_mem());
  if (bio == NULL) {
    LOG_OPENSSL_ERRORS(ERROR);
    return string();
  }

  if (ASN1_TIME_print(bio, when) != 1) {
    LOG_OPENSSL_ERRORS(ERROR);
    BIO_free(bio);
    return string();
  }

  string ret = util::ReadBIO(bio);
  BIO_free(bio);
  return ret;
}

Cert::Status Cert::IsIdenticalTo(const Cert &other) const {
  return X509_cmp(x509_, other.x509_) == 0 ? TRUE : FALSE;
}

Cert::Status Cert::HasExtension(int extension_nid) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  int ignored;
  return ExtensionIndex(extension_nid, &ignored);
}

Cert::Status Cert::HasCriticalExtension(int extension_nid) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  X509_EXTENSION *ext;
  Status status = GetExtension(extension_nid, &ext);
  if (status != TRUE)
    return status;

  return X509_EXTENSION_get_critical(ext) > 0 ? TRUE : FALSE;
}

Cert::Status Cert::HasBasicConstraintCATrue() const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  void *ext_struct;
  Status status = ExtensionStructure(NID_basic_constraints, &ext_struct);

  if (status == ERROR) {
    // Truly odd.
    LOG(ERROR) << "Failed to check BasicConstraints extension";
  }

  if (status != TRUE)
    return status;

  // |constraints| is never NULL upon success.
  BASIC_CONSTRAINTS *constraints = static_cast<BASIC_CONSTRAINTS*>(ext_struct);
  bool is_ca = constraints->ca;
  BASIC_CONSTRAINTS_free(constraints);
  return is_ca ? TRUE : FALSE;
}

Cert::Status Cert::HasExtendedKeyUsage(int key_usage_nid) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  ASN1_OBJECT *key_usage_obj = OBJ_nid2obj(key_usage_nid);
  if (key_usage_obj == NULL) {
    LOG(ERROR) << "OpenSSL OBJ_nid2obj returned NULL for NID "
               << key_usage_nid << ". Is the NID not recognised?";
    LOG_OPENSSL_ERRORS(WARNING);
    return ERROR;
  }

  void *ext_struct;
  Status status = ExtensionStructure(NID_ext_key_usage, &ext_struct);

  if (status == ERROR) {
    // Truly odd.
    LOG(ERROR) << "Failed to check ExtendedKeyUsage extension";
  }

  if (status != TRUE)
    return status;

  // |eku| is never NULL upon success.
  EXTENDED_KEY_USAGE *eku = static_cast<EXTENDED_KEY_USAGE*>(ext_struct);
  bool ext_key_usage_found = false;
  for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
    if (OBJ_cmp(key_usage_obj, sk_ASN1_OBJECT_value(eku, i)) == 0) {
      ext_key_usage_found = true;
      break;
    }
  }

  ASN1_OBJECT_free(key_usage_obj);
  EXTENDED_KEY_USAGE_free(eku);
  return ext_key_usage_found ? TRUE : FALSE;
}

Cert::Status Cert::IsIssuedBy(const Cert &issuer) const {
  if (!IsLoaded() || !issuer.IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }
  int ret = X509_check_issued(const_cast<X509*>(issuer.x509_), x509_);
  // Seemingly no negative "real" error codes are returned from here.
  return ret == X509_V_OK ? TRUE : FALSE;
}

Cert::Status Cert::IsSignedBy(const Cert &issuer) const {
  if (!IsLoaded() || !issuer.IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  EVP_PKEY *issuer_key = X509_get_pubkey(issuer.x509_);
  if (issuer_key == NULL) {
    LOG(WARNING) << "NULL issuer key";
    LOG_OPENSSL_ERRORS(WARNING);
    return FALSE;
  }

  int ret = X509_verify(x509_, issuer_key);
  EVP_PKEY_free(issuer_key);
  if (ret < 0) {
    unsigned long err = ERR_peek_last_error();
    int reason = ERR_GET_REASON(err);
    if (ERR_GET_LIB(err) == ERR_LIB_ASN1 &&
        (reason == ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM ||
         reason == ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM)) {
      LOG(WARNING) << "Unsupported algorithm: " << PrintSignatureAlgorithm();
      ClearOpenSSLErrors();
      return UNSUPPORTED_ALGORITHM;
    } else {
      LOG(ERROR) << "OpenSSL X509_verify returned error code " << ret;
      LOG_OPENSSL_ERRORS(ERROR);
      return ERROR;
    }
  }
  return ret > 0 ? TRUE : FALSE;
}

Cert::Status Cert::DerEncoding(string *result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  unsigned char *der_buf = NULL;
  int der_length = i2d_X509(x509_, &der_buf);

  if (der_length < 0) {
    // What does this return value mean? Let's assume it means the cert
    // is bad until proven otherwise.
    LOG(WARNING) << "Failed to serialize cert";
    LOG_OPENSSL_ERRORS(WARNING);
    return FALSE;
  }

  result->assign(reinterpret_cast<char*>(der_buf), der_length);
  OPENSSL_free(der_buf);
  return TRUE;
}

Cert::Status Cert::PemEncoding(string *result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  // TODO(pphaneuf): I would have liked to use std::unique_ptr, but it
  // is not available to us yet (C++11).
  shared_ptr<BIO> bp(BIO_new(BIO_s_mem()), BIO_free);
  if (!PEM_write_bio_X509(bp.get(), x509_)) {
    LOG(WARNING) << "Failed to serialize cert";
    LOG_OPENSSL_ERRORS(WARNING);
    return FALSE;
  }

  char *data;
  const long len(BIO_get_mem_data(bp.get(), &data));
  CHECK_GT(len, 0);
  CHECK(data);

  result->assign(data, len);

  return TRUE;
}

Cert::Status Cert::Sha256Digest(string *result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int len;
  if (X509_digest(x509_, EVP_sha256(), digest, &len) != 1) {
    // What does this return value mean? Let's assume it means the cert
    // is bad until proven otherwise.
    LOG(WARNING) << "Failed to compute cert digest";
    LOG_OPENSSL_ERRORS(WARNING);
    return FALSE;
  }

  result->assign(reinterpret_cast<char*>(digest), len);
  return TRUE;
}

Cert::Status Cert::DerEncodedTbsCertificate(string *result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  unsigned char *der_buf = NULL;
  int der_length = i2d_re_X509_tbs(x509_, &der_buf);
  if (der_length < 0) {
    // What does this return value mean? Let's assume it means the cert
    // is bad until proven otherwise.
    LOG(WARNING) << "Failed to serialize the TBS component";
    LOG_OPENSSL_ERRORS(WARNING);
    return FALSE;
  }
  result->assign(reinterpret_cast<char*>(der_buf), der_length);
  OPENSSL_free(der_buf);
  return TRUE;
}

Cert::Status Cert::DerEncodedSubjectName(string *result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }
  return DerEncodedName(X509_get_subject_name(x509_), result);
}

Cert::Status Cert::DerEncodedIssuerName(string *result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }
  return DerEncodedName(X509_get_issuer_name(x509_), result);
}

// static
Cert::Status Cert::DerEncodedName(X509_NAME *name, string *result) {
  unsigned char *der_buf = NULL;
  int der_length = i2d_X509_NAME(name, &der_buf);
  if (der_length < 0) {
    // What does this return value mean? Let's assume it means the cert
    // is bad until proven otherwise.
    LOG(WARNING) << "Failed to serialize the subject name";
    LOG_OPENSSL_ERRORS(WARNING);
    return FALSE;
  }
  result->assign(reinterpret_cast<char*>(der_buf), der_length);
  OPENSSL_free(der_buf);
  return TRUE;
}

Cert::Status Cert::PublicKeySha256Digest(string *result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int len;
  if (X509_pubkey_digest(x509_, EVP_sha256(), digest, &len) != 1) {
    // What does this return value mean? Let's assume it means the cert
    // is bad until proven otherwise.
    LOG(WARNING) << "Failed to compute public key digest";
    LOG_OPENSSL_ERRORS(WARNING);
    return FALSE;
  }
  result->assign(reinterpret_cast<char*>(digest), len);
  return TRUE;
}

Cert::Status Cert::SPKISha256Digest(string *result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  unsigned char *der_buf = NULL;
  int der_length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x509_), &der_buf);
  if (der_length < 0) {
    // What does this return value mean? Let's assume it means the cert
    // is bad until proven otherwise.
    LOG(WARNING) << "Failed to serialize the Subject Public Key Info";
    LOG_OPENSSL_ERRORS(WARNING);
    return FALSE;
  }

  string sha256_digest = Sha256Hasher::Sha256Digest(
      string(reinterpret_cast<char*>(der_buf), der_length));

  result->assign(sha256_digest);
  OPENSSL_free(der_buf);
  return TRUE;
}

Cert::Status Cert::OctetStringExtensionData(int extension_nid,
                                            string *result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  void *ext_data;
  Status status = ExtensionStructure(extension_nid, &ext_data);
  if (status != TRUE)
    return status;

  // |octet| is never NULL upon success. Caller is responsible for the
  // correctness of this cast.
  ASN1_OCTET_STRING *octet = static_cast<ASN1_OCTET_STRING*>(ext_data);
  result->assign(reinterpret_cast<const char*>(octet->data), octet->length);
  ASN1_OCTET_STRING_free(octet);
  return TRUE;
}

Cert::Status Cert::ExtensionIndex(int extension_nid,
                                  int *extension_index) const {
  int index = X509_get_ext_by_NID(x509_, extension_nid, -1);
  if (index < -1) {
    // The most likely and possibly only cause for a return code
    // other than -1 is an unrecognized NID.
    LOG(ERROR) << "OpenSSL X509_get_ext_by_NID returned " << index
               << " for NID " << extension_nid
               << ". Is the NID not recognised?";
    LOG_OPENSSL_ERRORS(ERROR);
    return ERROR;
  }
  if (index == -1)
    return FALSE;
  *extension_index = index;
  return TRUE;
}

Cert::Status Cert::GetExtension(int extension_nid,
                                X509_EXTENSION **ext) const {
  int extension_index;
  Status status = ExtensionIndex(extension_nid, &extension_index);
  if (status != TRUE)
    return status;

  *ext = X509_get_ext(x509_, extension_index);
  if (*ext == NULL) {
    LOG(ERROR) << "Failed to retrieve extension for NID " <<
        extension_nid << ", at index " << extension_index;
    LOG_OPENSSL_ERRORS(ERROR);
    return ERROR;
  } else {
    return TRUE;
  }
}

Cert::Status Cert::ExtensionStructure(int extension_nid,
                                      void **ext_struct) const {
  // Let's first check if the extension is present. This allows us to
  // distinguish between "NID not recognized" and the more harmless
  // "extension not found, found more than once or corrupt".
  Cert::Status status = HasExtension(extension_nid);
  if (status != TRUE)
    return status;

  int crit;
  *ext_struct = X509_get_ext_d2i(x509_, extension_nid, &crit, NULL);

  if (*ext_struct == NULL) {
    if (crit != -1) {
      LOG(WARNING) << "Corrupt extension data";
      LOG_OPENSSL_ERRORS(WARNING);
    }
    return FALSE;
  }

  return TRUE;
}

TbsCertificate::TbsCertificate(const Cert &cert)
    : x509_(NULL) {
  if (!cert.IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return;
  }

  x509_ = X509_dup(cert.x509_);

  if (x509_ == NULL)
    LOG_OPENSSL_ERRORS(ERROR);
}

TbsCertificate::~TbsCertificate() {
  if (x509_ != NULL)
    X509_free(x509_);
}

Cert::Status TbsCertificate::DerEncoding(std::string *result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "TBS not loaded";
    return Cert::ERROR;
  }

  unsigned char *der_buf = NULL;
  int der_length = i2d_re_X509_tbs(x509_, &der_buf);
  if (der_length < 0) {
    // What does this return value mean? Let's assume it means the cert
    // is bad until proven otherwise.
    LOG(WARNING) << "Failed to serialize the TBS component";
    LOG_OPENSSL_ERRORS(WARNING);
    return Cert::FALSE;
  }
  result->assign(reinterpret_cast<char*>(der_buf), der_length);
  OPENSSL_free(der_buf);
  return Cert::TRUE;
}

Cert::Status TbsCertificate::DeleteExtension(int extension_nid) {
  if (!IsLoaded()) {
    LOG(ERROR) << "TBS not loaded";
    return Cert::ERROR;
  }

  int extension_index;
  Cert::Status status = ExtensionIndex(extension_nid, &extension_index);
  if (status != Cert::TRUE)
    return status;

  X509_EXTENSION *ext = X509_delete_ext(x509_, extension_index);

  if (ext == NULL) {
    // Truly odd.
    LOG(ERROR) << "Failed to delete the extension";
    LOG_OPENSSL_ERRORS(ERROR);
    return Cert::ERROR;
  }

  // X509_delete_ext does not free the extension (GAH!), so we need to
  // free separately.
  X509_EXTENSION_free(ext);

  // ExtensionIndex returns the first matching index - if the extension
  // occurs more than once, just give up.
  int ignored;
  status = ExtensionIndex(extension_nid, &ignored);
  if (status == Cert::TRUE) {
    LOG(WARNING) << "Failed to delete the extension. Does the certificate have "
                 << "duplicate extensions?";
    return Cert::FALSE;
  }
  if (status != Cert::FALSE)
    return status;

  return Cert::TRUE;
}

Cert::Status TbsCertificate::CopyIssuerFrom(const Cert &from) {
  if (!from.IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return Cert::ERROR;
  }

  if (!IsLoaded()) {
    LOG(ERROR) << "TBS not loaded";
    return Cert::ERROR;
  }

  // This just looks up the relevant pointer so there shouldn't
  // be any errors to clear.
  X509_NAME *ca_name = X509_get_issuer_name(from.x509_);
  if (ca_name == NULL) {
    LOG(WARNING) << "Issuer certificate has NULL name";
    return Cert::FALSE;
  }

  if (X509_set_issuer_name(x509_, ca_name) != 1) {
    LOG(WARNING) << "Failed to set issuer name, Cert has NULL issuer?";
    LOG_OPENSSL_ERRORS(WARNING);
    return Cert::FALSE;
  }

  // Verify that the Authority KeyID extensions are compatible.
  int extension_index, from_extension_index;
  Cert::Status status = ExtensionIndex(NID_authority_key_identifier,
                                       &extension_index);
  if (status == Cert::FALSE) {
    // No extension found = nothing to copy
    return Cert::TRUE;
  }

  if (status != Cert::TRUE) {
    LOG(ERROR) << "Failed to check Authority Key Identifier extension";
    return Cert::ERROR;
  }

  status = from.ExtensionIndex(NID_authority_key_identifier,
                               &from_extension_index);

  if (status == Cert::FALSE) {
    // No extension found = cannot copy.
    LOG(WARNING) << "Unable to copy issuer: destination has an Authority "
                 << "KeyID extension, but the source has none.";
    return Cert::FALSE;
  }

  if (status != Cert::TRUE) {
    LOG(ERROR) << "Failed to check Authority Key Identifier extension";
    return Cert::ERROR;
  }

  // Ok, now copy the extension, keeping the critical bit (which should always
  // be false in a valid cert, mind you).
  X509_EXTENSION *to_ext = X509_get_ext(x509_, extension_index);
  X509_EXTENSION *from_ext = X509_get_ext(from.x509_, from_extension_index);

  if (to_ext == NULL || from_ext == NULL) {
    // Should not happen.
    LOG(ERROR) << "Failed to retrive extension";
    LOG_OPENSSL_ERRORS(ERROR);
    return Cert::ERROR;
  }

  if (X509_EXTENSION_set_data(to_ext, X509_EXTENSION_get_data(from_ext)) != 1) {
    LOG(ERROR) << "Failed to copy extension data.";
    LOG_OPENSSL_ERRORS(ERROR);
    return Cert::ERROR;
  }

  return Cert::TRUE;
}

Cert::Status TbsCertificate::ExtensionIndex(int extension_nid,
                                            int *extension_index) const {
  int index = X509_get_ext_by_NID(x509_, extension_nid, -1);
  if (index < -1) {
    // The most likely and possibly only cause for a return code
    // other than -1 is an unrecognized NID.
    LOG(ERROR) << "OpenSSL X509_get_ext_by_NID returned " << index
               << " for NID " << extension_nid
               << ". Is the NID not recognised?";
    LOG_OPENSSL_ERRORS(ERROR);
    return Cert::ERROR;
  }
  if (index == -1)
    return Cert::FALSE;
  *extension_index = index;
  return Cert::TRUE;
}

CertChain::CertChain(const string &pem_string) {
  // A read-only BIO.
  BIO *bio_in = BIO_new_mem_buf(const_cast<char*>(pem_string.data()),
                                pem_string.length());
  if (bio_in == NULL) {
    LOG_OPENSSL_ERRORS(ERROR);
    return;
  }

  X509 *x509 = NULL;
  while ((x509 = PEM_read_bio_X509(bio_in, NULL, NULL, NULL)) != NULL) {
    Cert *cert = new Cert(x509);
    chain_.push_back(cert);
  }

  BIO_free(bio_in);

  // The last error must be EOF.
  unsigned long err = ERR_peek_last_error();
  if (ERR_GET_LIB(err) != ERR_LIB_PEM ||
      ERR_GET_REASON(err) != PEM_R_NO_START_LINE) {
    // A real error.
    LOG(WARNING) << "Input is not a valid PEM-encoded certificate chain";
    LOG_OPENSSL_ERRORS(WARNING);
    ClearChain();
  } else {
    ClearOpenSSLErrors();
  }
}

Cert::Status CertChain::AddCert(Cert *cert) {
  if (cert == NULL || !cert->IsLoaded()) {
    LOG(ERROR) << "Attempting to add an invalid cert";
    if (cert != NULL)
      delete cert;
    return Cert::ERROR;
  }
  chain_.push_back(cert);
  return Cert::TRUE;
}

Cert::Status CertChain::RemoveCert() {
  if (!IsLoaded()) {
    LOG(ERROR) << "Chain is not loaded";
    return Cert::ERROR;
  }
  delete chain_.back();
  chain_.pop_back();
  return Cert::TRUE;
}

Cert::Status CertChain::RemoveCertsAfterFirstSelfSigned() {
  if (!IsLoaded()) {
    LOG(ERROR) << "Chain is not loaded";
    return Cert::ERROR;
  }

  size_t first_self_signed = chain_.size();

  // Find the first self-signed certificate.
  for (size_t i = 0; i < chain_.size(); ++i) {
    Cert::Status status = chain_[i]->IsSelfSigned();
    if (status != Cert::TRUE && status != Cert::FALSE)
      return Cert::ERROR;
    if (status == Cert::TRUE) {
      first_self_signed = i;
      break;
    }
  }

  if (first_self_signed == chain_.size())
    return Cert::TRUE;

  // Remove everything after it.
  size_t chain_size = chain_.size();
  for (size_t i = first_self_signed + 1; i < chain_size; ++i) {
    RemoveCert();
  }
  return Cert::TRUE;
}


CertChain::~CertChain() {
  ClearChain();
}

Cert::Status CertChain::IsValidCaIssuerChainMaybeLegacyRoot() const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Chain is not loaded";
    return Cert::ERROR;
  }

  Cert::Status status;
  for (std::vector<Cert*>::const_iterator it = chain_.begin();
       it + 1 < chain_.end(); ++it) {
    Cert *subject = *it;
    Cert *issuer = *(it + 1);

    // The root cert may not have CA:True
    status = issuer->IsSelfSigned();
    if (status == Cert::FALSE) {
      Cert::Status s2 = issuer->HasBasicConstraintCATrue();
      if (s2 != Cert::TRUE)
        return s2;
    } else if (status != Cert::TRUE) {
      LOG(ERROR) << "Failed to check self-signed status";
      return Cert::ERROR;
    }

    status = subject->IsIssuedBy(*issuer);
    if (status != Cert::TRUE)
      return status;
  }
  return Cert::TRUE;
}

Cert::Status CertChain::IsValidSignatureChain() const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Chain is not loaded";
    return Cert::ERROR;
  }

  Cert::Status status;
  for (std::vector<Cert*>::const_iterator it = chain_.begin();
       it + 1 < chain_.end(); ++it) {
    Cert *subject = *it;
    Cert *issuer = *(it + 1);
    status = subject->IsSignedBy(*issuer);
    if (status != Cert::TRUE)
      return status;
  }
  return Cert::TRUE;
}

void CertChain::ClearChain() {
  std::vector<Cert*>::const_iterator it;
  for (it = chain_.begin(); it < chain_.end(); ++it)
    delete *it;
  chain_.clear();
}

Cert::Status PreCertChain::UsesPrecertSigningCertificate() const {
  const Cert *issuer = PrecertIssuingCert();
  if (issuer == NULL) {
    // No issuer, so it must be a real root CA from the store.
    return Cert::FALSE;
  }

  return issuer->HasExtendedKeyUsage(ct::NID_ctPrecertificateSigning);
}

Cert::Status PreCertChain::IsWellFormed() const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Chain is not loaded";
    return Cert::ERROR;
  }

  const Cert *pre = PreCert();

  // (1) Check that the leaf contains the critical poison extension.
  Cert::Status status = pre->HasCriticalExtension(ct::NID_ctPoison);
  if (status != Cert::TRUE)
    return status;

  // (2) If signed by a Precertificate Signing Certificate, check that
  // the AKID extensions are compatible.
  status = UsesPrecertSigningCertificate();
  if (status == Cert::FALSE) {
    // If there is no precert signing extendedKeyUsage, no more checks:
    // the cert was issued by a regular CA.
    return Cert::TRUE;
  }
  if (status != Cert::TRUE)
    return status;

  const Cert *issuer = PrecertIssuingCert();
  // If pre has the extension set but the issuer doesn't, error.
  status = pre->HasExtension(NID_authority_key_identifier);
  if (status == Cert::FALSE)
    return Cert::TRUE;
  if (status != Cert::TRUE)
    return status;
  // Extension present in the leaf: check it's present in the issuer.
  return issuer->HasExtension(NID_authority_key_identifier);
}

}  // namespace ct
