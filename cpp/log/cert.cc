/* -*- indent-tabs-mode: nil -*- */
#include "log/cert.h"
#include "log/ct_extensions.h"
#include "merkletree/serial_hasher.h"
#include "util/openssl_util.h"  // For LOG_OPENSSL_ERRORS
#include "util/util.h"

#include <glog/logging.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <memory>
#include <string>
#include <time.h>
#include <vector>

using std::string;
using std::unique_ptr;
using std::vector;
using util::ClearOpenSSLErrors;
using util::StatusOr;
using util::error::Code;

#if OPENSSL_VERSION_NUMBER < 0x10002000L
// Backport from 1.0.2-beta3.
static int i2d_re_X509_tbs(X509* x, unsigned char** pp) {
  x->cert_info->enc.modified = 1;
  return i2d_X509_CINF(x->cert_info, pp);
}

static int X509_get_signature_nid(const X509* x) {
  return OBJ_obj2nid(x->sig_alg->algorithm);
}
#endif

namespace {
// TODO. These helpers can be removed when Cert::Status has been removed.
// They make it easier to do an incremental removal

cert_trans::Cert::Status StatusOrBoolToCertStatus(StatusOr<bool> status) {
  if (status.ok()) {
    return status.ValueOrDie() ? cert_trans::Cert::TRUE
                               : cert_trans::Cert::FALSE;
  } else {
    return cert_trans::Cert::ERROR;
  }
}


StatusOr<bool> CertStatusToStatusOrBool(cert_trans::Cert::Status status) {
  if (status == cert_trans::Cert::FALSE) {
    return false;
  } else if (status == cert_trans::Cert::TRUE) {
    return true;
  } else {
    return util::Status(Code::UNKNOWN, "Unknown status");
  }
}

// END of section to be cleaned up

}

namespace cert_trans {

// Convert string from ASN1 and check it doesn't contain nul characters
string ASN1ToStringAndCheckForNulls(ASN1_STRING* asn1_string,
                                    const string& tag,
                                    Cert::Status* status) {
  const string cpp_string(reinterpret_cast<char*>(
      ASN1_STRING_data(asn1_string)), ASN1_STRING_length(asn1_string));

  // Make sure there isn't an embedded NUL character in the DNS ID
  if (ASN1_STRING_length(asn1_string) != cpp_string.length()) {
    LOG(ERROR) << "Embedded null in asn1 string: " << tag;
    *status = Cert::ERROR;
  } else {
    *status = Cert::TRUE;
  }

  return cpp_string;
}


Cert::Cert(X509* x509) : x509_(x509) {
}


Cert::Cert(const string& pem_string) : x509_(nullptr) {
  // A read-only bio.
  BIO* bio_in = BIO_new_mem_buf(const_cast<char*>(pem_string.data()),
                                pem_string.length());
  if (!bio_in) {
    LOG_OPENSSL_ERRORS(ERROR);
    return;
  }

  x509_ = PEM_read_bio_X509(bio_in, nullptr, nullptr, nullptr);
  BIO_free(bio_in);

  if (!x509_) {
    // At this point most likely the input was just corrupt. There are a few
    // real errors that may have happened (a malloc failure is one) and it is
    // virtually impossible to fish them out.
    LOG(WARNING) << "Input is not a valid PEM-encoded certificate";
    LOG_OPENSSL_ERRORS(WARNING);
  }
}


Cert::~Cert() {
  if (x509_)
    X509_free(x509_);
}


Cert* Cert::Clone() const {
  X509* x509(nullptr);
  if (x509_) {
    x509 = X509_dup(x509_);
    if (!x509)
      LOG_OPENSSL_ERRORS(ERROR);
  }
  return new Cert(x509);
}


Cert::Status Cert::LoadFromDerString(const string& der_string) {
  if (x509_) {
    X509_free(x509_);
    x509_ = nullptr;
  }
  const unsigned char* start =
      reinterpret_cast<const unsigned char*>(der_string.data());
  x509_ = d2i_X509(nullptr, &start, der_string.size());
  if (!x509_) {
    LOG(WARNING) << "Input is not a valid DER-encoded certificate";
    LOG_OPENSSL_ERRORS(WARNING);
    return Cert::FALSE;
  }
  return Cert::TRUE;
}


Cert::Status Cert::LoadFromDerBio(BIO* bio_in) {
  if (x509_) {
    // TODO(AlCutter): Use custom deallocator
    X509_free(x509_);
    x509_ = nullptr;
  }

  x509_ = d2i_X509_bio(bio_in, &x509_);
  CHECK_NOTNULL(bio_in);

  if (!x509_) {
    // At this point most likely the input was just corrupt. There are few
    // real errors that may have happened (a malloc failure is one) and it is
    // virtually impossible to fish them out.
    LOG(WARNING) << "Input is not a valid encoded certificate";
    LOG_OPENSSL_ERRORS(WARNING);
    return Cert::FALSE;
  }
  return TRUE;
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
string Cert::PrintName(X509_NAME* name) {
  if (!name)
    return string();
  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
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
  const char* sigalg = OBJ_nid2ln(X509_get_signature_nid(x509_));
  if (!sigalg)
    return "NULL";
  return string(sigalg);
}


// static
string Cert::PrintTime(ASN1_TIME* when) {
  if (!when)
    return string();

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
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


bool Cert::IsIdenticalTo(const Cert& other) const {
  return X509_cmp(x509_, other.x509_) == 0;
}


Cert::Status Cert::HasExtension(int extension_nid) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  const StatusOr<int> index(ExtensionIndex(extension_nid));
  if (index.ok()) {
    return TRUE;
  }

  if (index.status().CanonicalCode() == util::error::NOT_FOUND) {
    return FALSE;
  }

  return ERROR;
}


Cert::Status Cert::HasCriticalExtension(int extension_nid) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  X509_EXTENSION* ext;
  Status status = GetExtension(extension_nid, &ext);
  if (status != TRUE)
    return status;

  return X509_EXTENSION_get_critical(ext) > 0 ? TRUE : FALSE;
}


StatusOr<bool> Cert::HasBasicConstraintCATrue() const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return util::Status(Code::FAILED_PRECONDITION, "Cert not loaded");
  }

  void* ext_struct;
  Status status = ExtensionStructure(NID_basic_constraints, &ext_struct);

  if (status == ERROR) {
    // Truly odd.
    LOG(ERROR) << "Failed to check BasicConstraints extension";
  }

  if (status != TRUE) {
    return CertStatusToStatusOrBool(status);
  }

  // |constraints| is never null upon success.
  BASIC_CONSTRAINTS* constraints = static_cast<BASIC_CONSTRAINTS*>(ext_struct);
  bool is_ca = constraints->ca;
  BASIC_CONSTRAINTS_free(constraints);
  return is_ca;
}


StatusOr<bool> Cert::HasExtendedKeyUsage(int key_usage_nid) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return util::Status(Code::FAILED_PRECONDITION, "Cert not loaded");
  }

  const ASN1_OBJECT* key_usage_obj = OBJ_nid2obj(key_usage_nid);
  if (!key_usage_obj) {
    LOG(ERROR) << "OpenSSL OBJ_nid2obj returned NULL for NID " << key_usage_nid
               << ". Is the NID not recognised?";
    LOG_OPENSSL_ERRORS(WARNING);
    return util::Status(Code::INTERNAL, "NID lookup failed");
  }

  void* ext_struct;
  Status status = ExtensionStructure(NID_ext_key_usage, &ext_struct);

  if (status == ERROR) {
    // Truly odd.
    LOG(ERROR) << "Failed to check ExtendedKeyUsage extension";
  }

  if (status != TRUE) {
    return CertStatusToStatusOrBool(status);
  }

  // |eku| is never null upon success.
  EXTENDED_KEY_USAGE* eku = static_cast<EXTENDED_KEY_USAGE*>(ext_struct);
  bool ext_key_usage_found = false;
  for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
    if (OBJ_cmp(key_usage_obj, sk_ASN1_OBJECT_value(eku, i)) == 0) {
      ext_key_usage_found = true;
      break;
    }
  }

  EXTENDED_KEY_USAGE_free(eku);
  return ext_key_usage_found;
}


Cert::Status Cert::IsIssuedBy(const Cert& issuer) const {
  if (!IsLoaded() || !issuer.IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }
  int ret = X509_check_issued(const_cast<X509*>(issuer.x509_), x509_);
  // Seemingly no negative "real" error codes are returned from here.
  return ret == X509_V_OK ? TRUE : FALSE;
}


Cert::Status Cert::IsSignedBy(const Cert& issuer) const {
  if (!IsLoaded() || !issuer.IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  EVP_PKEY* issuer_key = X509_get_pubkey(issuer.x509_);
  if (!issuer_key) {
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


Cert::Status Cert::DerEncoding(string* result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  unsigned char* der_buf(nullptr);
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


Cert::Status Cert::PemEncoding(string* result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  unique_ptr<BIO, int (*)(BIO*)> bp(BIO_new(BIO_s_mem()), &BIO_free);
  if (!PEM_write_bio_X509(bp.get(), x509_)) {
    LOG(WARNING) << "Failed to serialize cert";
    LOG_OPENSSL_ERRORS(WARNING);
    return FALSE;
  }

  char* data;
  const long len(BIO_get_mem_data(bp.get(), &data));
  CHECK_GT(len, 0);
  CHECK(data);

  result->assign(data, len);

  return TRUE;
}


Cert::Status Cert::Sha256Digest(string* result) const {
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


Cert::Status Cert::DerEncodedTbsCertificate(string* result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  unsigned char* der_buf(nullptr);
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


Cert::Status Cert::DerEncodedSubjectName(string* result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }
  return DerEncodedName(X509_get_subject_name(x509_), result);
}


Cert::Status Cert::DerEncodedIssuerName(string* result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }
  return DerEncodedName(X509_get_issuer_name(x509_), result);
}


// static
Cert::Status Cert::DerEncodedName(X509_NAME* name, string* result) {
  unsigned char* der_buf(nullptr);
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


Cert::Status Cert::PublicKeySha256Digest(string* result) const {
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


Cert::Status Cert::SPKISha256Digest(string* result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  unsigned char* der_buf(nullptr);
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
                                            string* result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return ERROR;
  }

  void* ext_data;
  Status status = ExtensionStructure(extension_nid, &ext_data);
  if (status != TRUE)
    return status;

  // |octet| is never null upon success. Caller is responsible for the
  // correctness of this cast.
  ASN1_OCTET_STRING* octet = static_cast<ASN1_OCTET_STRING*>(ext_data);
  result->assign(reinterpret_cast<const char*>(octet->data), octet->length);
  ASN1_OCTET_STRING_free(octet);
  return TRUE;
}


util::StatusOr<int> Cert::ExtensionIndex(int extension_nid) const {
  const int index(X509_get_ext_by_NID(x509_, extension_nid, -1));
  if (index < -1) {
    // The most likely and possibly only cause for a return code
    // other than -1 is an unrecognized NID.
    LOG(ERROR) << "OpenSSL X509_get_ext_by_NID returned " << index
               << " for NID " << extension_nid
               << ". Is the NID not recognised?";
    LOG_OPENSSL_ERRORS(ERROR);
    return util::Status(util::error::INTERNAL, "X509_get_ext_by_NID error");
  }
  if (index == -1)
    return util::Status(util::error::NOT_FOUND, "extension not found");
  return index;
}


Cert::Status Cert::GetExtension(int extension_nid,
                                X509_EXTENSION** ext) const {
  const StatusOr<int> extension_index(ExtensionIndex(extension_nid));
  if (!extension_index.ok()) {
    return extension_index.status().CanonicalCode() == util::error::NOT_FOUND
               ? FALSE
               : ERROR;
  }

  *ext = X509_get_ext(x509_, extension_index.ValueOrDie());
  if (!*ext) {
    LOG(ERROR) << "Failed to retrieve extension for NID " << extension_nid
               << ", at index " << extension_index.ValueOrDie();
    LOG_OPENSSL_ERRORS(ERROR);
    return ERROR;
  } else {
    return TRUE;
  }
}


Cert::Status Cert::ExtensionStructure(int extension_nid,
                                      void** ext_struct) const {
  // Let's first check if the extension is present. This allows us to
  // distinguish between "NID not recognized" and the more harmless
  // "extension not found, found more than once or corrupt".
  Cert::Status status = HasExtension(extension_nid);
  if (status != TRUE)
    return status;

  int crit;

  *ext_struct = X509_get_ext_d2i(x509_, extension_nid, &crit, nullptr);

  if (!*ext_struct) {
    if (crit != -1) {
      LOG(WARNING) << "Corrupt extension data";
      LOG_OPENSSL_ERRORS(WARNING);
    }

    return FALSE;
  }

  return TRUE;
}


bool IsRedactedHost(const string& hostname) {
  // Split the hostname on '.' characters
  const vector<string> tokens(util::split(hostname, '.'));

  for (const string& str : tokens) {
    if (str == "?") {
      return true;
    }
  }

  return false;
}


bool IsValidRedactedHost(const string& hostname) {
  // Split the hostname on '.' characters
  const vector<string> tokens(util::split(hostname, '.'));

  // Enforces the following rules: '?' must be to left of non redactions
  // If first label is '*' then treat it as if it was a redaction
  bool can_redact = true;
  for (int pos = 0; pos < tokens.size(); ++pos) {
    if (tokens[pos] == "?") {
      if (!can_redact) {
        return false;
      }
    } else {
      // Allow a leading '*' for redaction but once we've seen anything else
      // forbid further redactions
      if (tokens[pos] != "*") {
        can_redact = false;
      } else if (pos > 0) {
        // '*' is only valid at the left
        return false;
      }
    }
  }

  return true;
}


bool validateRedactionSubjectAltNames(STACK_OF(GENERAL_NAME)* subject_alt_names,
                                      vector<string>* dns_alt_names,
                                      Cert::Status* status,
                                      int* redacted_name_count) {
  // First. Check all the Subject Alt Name extension records. Any that are of
  // type DNS must pass validation if they are attempting to redact labels
  if (subject_alt_names) {
    const int subject_alt_name_count = sk_GENERAL_NAME_num(subject_alt_names);

    for (int i = 0; i < subject_alt_name_count; ++i) {
      GENERAL_NAME* const name(sk_GENERAL_NAME_value(subject_alt_names, i));

      Cert::Status name_status;

      if (name->type == GEN_DNS) {
        const string dns_name = ASN1ToStringAndCheckForNulls(name->d.dNSName,
                                                             "DNS name",
                                                             &name_status);

        if (name_status != Cert::TRUE) {
          sk_GENERAL_NAME_free(subject_alt_names);
          *status = name_status;
          return true;
        }

        dns_alt_names->push_back(dns_name);

        if (IsRedactedHost(dns_name)) {
          if (!IsValidRedactedHost(dns_name)) {
            LOG(WARNING) << "Invalid redacted host: " << dns_name;
            sk_GENERAL_NAME_free(subject_alt_names);
            *status = Cert::FALSE;
            return true;
          }

          redacted_name_count++;
        }
      }
    }

    sk_GENERAL_NAME_free(subject_alt_names);
  }

  // This stage of validation is complete, result is not final yet
  return false;
}


// Helper method for validating V2 redaction rules. If it returns true
// then the result in status is final.
bool Cert::ValidateRedactionSubjectAltNameAndCN(int* dns_alt_name_count,
                                                Status* status) const {
  string common_name;
  int redacted_name_count = 0;
  vector<string> dns_alt_names;

  STACK_OF(GENERAL_NAME)* subject_alt_names =
      static_cast<STACK_OF(GENERAL_NAME)*>(
          X509_get_ext_d2i(x509_, NID_subject_alt_name, nullptr, nullptr));

  // Apply validation rules for subject alt names, if this returns true
  // status is already final.
  if (subject_alt_names &&
      validateRedactionSubjectAltNames(subject_alt_names,
                                       &dns_alt_names,
                                       status,
                                       &redacted_name_count)) {
    return true;
  }

  // The next stage of validation is that if the subject name CN exists it
  // must match the first DNS id and have the same labels redacted
  // TODO: Confirm it's valid to not have a CN.
  X509_NAME* const name(X509_get_subject_name(x509_));

  if (!name) {
    LOG(ERROR) << "Missing X509 subject name";
    *status = Cert::ERROR;
    return true;
  }

  const int name_pos(
      X509_NAME_get_index_by_NID(name, NID_commonName, -1));

  if (name_pos >= 0) {
    X509_NAME_ENTRY* const name_entry(X509_NAME_get_entry(name, name_pos));

    if (name_entry) {
      ASN1_STRING* const subject_name_asn1(
          X509_NAME_ENTRY_get_data(name_entry));

      if (!subject_name_asn1) {
        LOG(WARNING) << "Missing subject name";
        // TODO: Check this is correct behaviour. Is it OK to not have
        // a subject?
      } else {
        Cert::Status cn_status;
        common_name = ASN1ToStringAndCheckForNulls(subject_name_asn1,
                                                   "CN", &cn_status);

        if (cn_status != TRUE) {
          *status = cn_status;
          return true;
        }
      }
    }
  }

  // If both a subject CN and DNS ids are present in the cert then the
  // first DNS id must exactly match the CN
  if (!dns_alt_names.empty() && !common_name.empty()) {
    if (dns_alt_names[0] != common_name) {
      LOG(WARNING) << "CN " << common_name << " does not match DNS.0 "
                   << dns_alt_names[0];
      *status = Cert::FALSE;
      return true;
    }
  }

  // The attempted redaction passes host validation. Stage two is checking
  // that the required extensions are present and specified correctly if
  // we found any redacted names. First though if nothing is redacted
  // then the rest of the rules need not be applied
  if (redacted_name_count == 0 && !IsRedactedHost(common_name)) {
    *status = Cert::TRUE;
    return true;
  }

  *dns_alt_name_count = dns_alt_names.size();
  return false;  // validation has no definite result yet
}


Cert::Status Cert::IsValidWildcardRedaction() const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return Cert::ERROR;
  }

  Cert::Status status(ERROR);
  int dns_alt_name_count = 0;

  // First we apply all the checks to the subject CN and the list of DNS
  // names in subject alt names. If these checks have a definite result
  // then return it immediately.
  if (ValidateRedactionSubjectAltNameAndCN(&dns_alt_name_count, &status)) {
    return status;
  }

  // If we reach here then the RFC says the CT redaction count extension
  // MUST BE present.
  X509_EXTENSION* exty;
  if (GetExtension(NID_ctPrecertificateRedactedLabelCount,
                   &exty) != Cert::TRUE) {
    LOG(WARNING) << "Required CT redaction count extension missing from cert";
    return Cert::FALSE;
  }

  // Unpack the extension contents, which should be SEQUENCE OF INTEGER
  STACK_OF(ASN1_INTEGER)* const integers(static_cast<STACK_OF(ASN1_INTEGER)*>(
      ASN1_seq_unpack_ASN1_INTEGER(exty->value->data, exty->value->length,
                                   d2i_ASN1_INTEGER, ASN1_INTEGER_free)));

  if (integers) {
    const int num_integers = sk_ASN1_INTEGER_num(integers);

    // RFC text says there MUST NOT be more integers than there are DNS ids
    if (num_integers > dns_alt_name_count) {
      LOG(WARNING) << "Too many integers in extension: " << num_integers
                   << " but only " << dns_alt_name_count << " DNS names";
      sk_ASN1_INTEGER_free(integers);
      return Cert::FALSE;
    }

    // All the integers in the sequence must be positive, check the sign
    // after conversion to BIGNUM
    for (int i = 0; i < num_integers; ++i) {
      ASN1_INTEGER* const redacted_labels(sk_ASN1_INTEGER_value(integers, i));
      BIGNUM* const value(ASN1_INTEGER_to_BN(redacted_labels, nullptr));

      const bool neg = value->neg;
      ASN1_INTEGER_free(redacted_labels);

      if (neg) {
        LOG(WARNING) << "Invalid negative redaction label count: "
                     << BN_bn2hex(value);
        BN_free(value);
        sk_ASN1_INTEGER_free(integers);
        return Cert::FALSE;
      }

      BN_free(value);
    }

    sk_ASN1_INTEGER_free(integers);
  } else {
    LOG(WARNING) << "Failed to unpack SEQUENCE OF in CT extension";
    return Cert::FALSE;
  }

  return Cert::TRUE;
}


Cert::Status Cert::IsValidNameConstrainedIntermediateCa() const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return Cert::ERROR;
  }

  // If it's not a CA cert or there is no name constraint extension then we
  // don't need to apply the rules any further
  StatusOr<bool> has_ca_constraint = HasBasicConstraintCATrue();
  if (!has_ca_constraint.ok() || !has_ca_constraint.ValueOrDie()
      || HasExtension(NID_name_constraints) == Cert::FALSE) {
    return Cert::TRUE;
  }

  // So there now must be a CT extension and the name constraint must not be
  // in error
  if (HasExtension(NID_name_constraints) != Cert::TRUE
      || HasExtension(NID_ctNameConstraintNologIntermediateCa) != Cert::TRUE) {
    LOG(WARNING) < "Name constraint extension without CT extension";
    return Cert::FALSE;
  }

  int crit;
  NAME_CONSTRAINTS* const nc(static_cast<NAME_CONSTRAINTS*>(X509_get_ext_d2i(
      x509_, NID_name_constraints, &crit, nullptr)));

  if (!nc || crit == -1) {
    LOG(ERROR) << "Couldn't parse the name constraint extension";
    return Cert::ERROR;
  }

  // Search all the permitted subtrees, there must be at least one DNS
  // entry and it must not be empty
  bool seen_dns = false;

  for (int permitted_subtree = 0;
      permitted_subtree < sk_GENERAL_SUBTREE_num(nc->permittedSubtrees);
      ++permitted_subtree) {
    GENERAL_SUBTREE* const perm_subtree(sk_GENERAL_SUBTREE_value(
        nc->permittedSubtrees, permitted_subtree));

    if (perm_subtree->base && perm_subtree->base->type == GEN_DNS
        && perm_subtree->base->d.dNSName->length > 0) {
      seen_dns = true;
    }
  }

  // There must be an excluded subtree entry that covers the whole IPv4 and
  // IPv6 range. Or at least one entry for both that covers the whole
  // range
  bool seen_ipv4 = false;
  bool seen_ipv6 = false;

  // TODO: Does not handle more complex cases at the moment and I'm
  // not sure whether it should. E.g. a combination of multiple entries
  // that end up covering the whole available range. For the moment
  // things similar to the example in the RFC work.
  for (int excluded_subtree = 0;
      excluded_subtree < sk_GENERAL_SUBTREE_num(nc->excludedSubtrees);
      ++excluded_subtree) {

    GENERAL_SUBTREE* const excl_subtree(sk_GENERAL_SUBTREE_value(
        nc->excludedSubtrees, excluded_subtree));

    // Only consider entries that are of type ipAddress (OCTET_STRING)
    if (excl_subtree->base && excl_subtree->base->type == GEN_IPADD) {
      // First check that all the bytes of the string are zero
      bool all_zero = true;
      for (int i = 0; i < excl_subtree->base->d.ip->length; ++i) {
        if (excl_subtree->base->d.ip->data[i] != 0) {
          all_zero = false;
        }
      }

      if (all_zero) {
        if (excl_subtree->base->d.ip->length == 32) {
          // IPv6
          seen_ipv6 = true;
        } else if (excl_subtree->base->d.ip->length == 8) {
          // IPv4
          seen_ipv4 = true;
        }
      }
    }
  }

  NAME_CONSTRAINTS_free(nc);

  if (!seen_dns) {
    LOG(WARNING) << "No DNS entry found in permitted subtrees";
    return Cert::FALSE;
  }

  if (!seen_ipv4 || !seen_ipv6) {
    LOG(WARNING) << "Excluded subtree does not cover all IPv4 and v6 range";
    return Cert::FALSE;
  }

  return TRUE;
}


TbsCertificate::TbsCertificate(const Cert& cert) : x509_(nullptr) {
  if (!cert.IsLoaded()) {
    LOG(ERROR) << "Cert not loaded";
    return;
  }

  x509_ = X509_dup(cert.x509_);

  if (!x509_)
    LOG_OPENSSL_ERRORS(ERROR);
}


TbsCertificate::~TbsCertificate() {
  if (x509_)
    X509_free(x509_);
}


Cert::Status TbsCertificate::DerEncoding(string* result) const {
  if (!IsLoaded()) {
    LOG(ERROR) << "TBS not loaded";
    return Cert::ERROR;
  }

  unsigned char* der_buf(nullptr);
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

  X509_EXTENSION* ext = X509_delete_ext(x509_, extension_index);

  if (!ext) {
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
    LOG(WARNING)
        << "Failed to delete the extension. Does the certificate have "
        << "duplicate extensions?";
    return Cert::FALSE;
  }
  if (status != Cert::FALSE)
    return status;

  return Cert::TRUE;
}


Cert::Status TbsCertificate::CopyIssuerFrom(const Cert& from) {
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
  X509_NAME* ca_name = X509_get_issuer_name(from.x509_);
  if (!ca_name) {
    LOG(WARNING) << "Issuer certificate has NULL name";
    return Cert::FALSE;
  }

  if (X509_set_issuer_name(x509_, ca_name) != 1) {
    LOG(WARNING) << "Failed to set issuer name, Cert has NULL issuer?";
    LOG_OPENSSL_ERRORS(WARNING);
    return Cert::FALSE;
  }

  // Verify that the Authority KeyID extensions are compatible.
  int extension_index;
  Cert::Status status =
      ExtensionIndex(NID_authority_key_identifier, &extension_index);
  if (status == Cert::FALSE) {
    // No extension found = nothing to copy
    return Cert::TRUE;
  }

  if (status != Cert::TRUE) {
    LOG(ERROR) << "Failed to check Authority Key Identifier extension";
    return Cert::ERROR;
  }

  const StatusOr<int> from_extension_index(
      from.ExtensionIndex(NID_authority_key_identifier));
  if (from_extension_index.status().CanonicalCode() ==
      util::error::NOT_FOUND) {
    // No extension found = cannot copy.
    LOG(WARNING) << "Unable to copy issuer: destination has an Authority "
                 << "KeyID extension, but the source has none.";
    return Cert::FALSE;
  }

  if (!from_extension_index.ok()) {
    LOG(ERROR) << "Failed to check Authority Key Identifier extension";
    return Cert::ERROR;
  }

  // Ok, now copy the extension, keeping the critical bit (which should always
  // be false in a valid cert, mind you).
  X509_EXTENSION* to_ext = X509_get_ext(x509_, extension_index);
  X509_EXTENSION* from_ext =
      X509_get_ext(from.x509_, from_extension_index.ValueOrDie());

  if (!to_ext || !from_ext) {
    // Should not happen.
    LOG(ERROR) << "Failed to retrive extension";
    LOG_OPENSSL_ERRORS(ERROR);
    return Cert::ERROR;
  }

  if (X509_EXTENSION_set_data(to_ext, X509_EXTENSION_get_data(from_ext)) !=
      1) {
    LOG(ERROR) << "Failed to copy extension data.";
    LOG_OPENSSL_ERRORS(ERROR);
    return Cert::ERROR;
  }

  return Cert::TRUE;
}


Cert::Status TbsCertificate::ExtensionIndex(int extension_nid,
                                            int* extension_index) const {
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


CertChain::CertChain(const string& pem_string) {
  // A read-only BIO.
  BIO* const bio_in(BIO_new_mem_buf(const_cast<char*>(pem_string.data()),
                                    pem_string.length()));
  if (!bio_in) {
    LOG_OPENSSL_ERRORS(ERROR);
    return;
  }

  X509* x509(nullptr);
  while ((x509 = PEM_read_bio_X509(bio_in, nullptr, nullptr, nullptr))) {
    chain_.push_back(new Cert(x509));
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


Cert::Status CertChain::AddCert(Cert* cert) {
  if (!cert || !cert->IsLoaded()) {
    LOG(ERROR) << "Attempting to add an invalid cert";
    if (cert)
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
  for (vector<Cert*>::const_iterator it = chain_.begin();
       it + 1 < chain_.end(); ++it) {
    Cert* subject = *it;
    Cert* issuer = *(it + 1);

    // The root cert may not have CA:True
    status = issuer->IsSelfSigned();
    if (status == Cert::FALSE) {
      StatusOr<bool> s2 = issuer->HasBasicConstraintCATrue();
      if (StatusOrBoolToCertStatus(s2) != Cert::TRUE) {
        return StatusOrBoolToCertStatus(s2);
      }
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
  for (vector<Cert*>::const_iterator it = chain_.begin();
       it + 1 < chain_.end(); ++it) {
    Cert* subject = *it;
    Cert* issuer = *(it + 1);
    status = subject->IsSignedBy(*issuer);
    if (status != Cert::TRUE)
      return status;
  }
  return Cert::TRUE;
}


void CertChain::ClearChain() {
  vector<Cert*>::const_iterator it;
  for (it = chain_.begin(); it < chain_.end(); ++it)
    delete *it;
  chain_.clear();
}


Cert::Status PreCertChain::UsesPrecertSigningCertificate() const {
  const Cert* issuer = PrecertIssuingCert();
  if (!issuer) {
    // No issuer, so it must be a real root CA from the store.
    return Cert::FALSE;
  }

  return StatusOrBoolToCertStatus(
      issuer->HasExtendedKeyUsage(cert_trans::NID_ctPrecertificateSigning));
}


Cert::Status PreCertChain::IsWellFormed() const {
  if (!IsLoaded()) {
    LOG(ERROR) << "Chain is not loaded";
    return Cert::ERROR;
  }

  const Cert* pre = PreCert();

  // (1) Check that the leaf contains the critical poison extension.
  Cert::Status status = pre->HasCriticalExtension(cert_trans::NID_ctPoison);
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

  const Cert* issuer = PrecertIssuingCert();
  // If pre has the extension set but the issuer doesn't, error.
  status = pre->HasExtension(NID_authority_key_identifier);
  if (status == Cert::FALSE)
    return Cert::TRUE;
  if (status != Cert::TRUE)
    return status;
  // Extension present in the leaf: check it's present in the issuer.
  return issuer->HasExtension(NID_authority_key_identifier);
}

}  // namespace cert_trans
