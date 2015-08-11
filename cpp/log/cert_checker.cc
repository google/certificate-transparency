/* -*- indent-tabs-mode: nil -*- */
#include "log/cert_checker.h"

#include <glog/logging.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <string>
#include <utility>
#include <vector>

#include "log/cert.h"
#include "log/ct_extensions.h"
#include "util/openssl_util.h"  // for LOG_OPENSSL_ERRORS
#include "util/util.h"

using std::string;
using std::vector;
using util::ClearOpenSSLErrors;

namespace cert_trans {

CertChecker::~CertChecker() { ClearAllTrustedCertificates(); }

bool CertChecker::LoadTrustedCertificates(const string& cert_file) {
  // A read-only BIO.
  BIO* bio_in = BIO_new(BIO_s_file());
  if (bio_in == NULL) {
    LOG_OPENSSL_ERRORS(ERROR);
    return false;
  }

  if (BIO_read_filename(bio_in, cert_file.c_str()) <= 0) {
    BIO_free(bio_in);
    LOG(ERROR) << "Failed to open file " << cert_file << " for reading";
    LOG_OPENSSL_ERRORS(ERROR);
    return false;
  }

  return LoadTrustedCertificatesFromBIO(bio_in);
}

bool CertChecker::LoadTrustedCertificates(const vector<string>& trusted_certs) {
  string concat_certs;
  for (vector<string>::const_iterator it = trusted_certs.begin();
       it != trusted_certs.end(); ++it) {
    concat_certs.append(*it);
  }
  // A read-only memory BIO.
  BIO* bio_in = BIO_new_mem_buf(
      const_cast<void*>(reinterpret_cast<const void*>(concat_certs.c_str())),
      -1 /* no length, since null-terminated */);
  if (bio_in == NULL) {
    LOG_OPENSSL_ERRORS(ERROR);
    return false;
  }

  return LoadTrustedCertificatesFromBIO(bio_in);
}

bool CertChecker::LoadTrustedCertificatesFromBIO(BIO* bio_in) {
  CHECK(bio_in != NULL);
  std::vector<std::pair<string, Cert*> > certs_to_add;
  bool error = false;
  // certs_to_add may be empty if no new certs were added, so keep track of
  // successfully parsed cert count separately.
  size_t cert_count = 0;

  while (!error) {
    X509* x509 = PEM_read_bio_X509(bio_in, NULL, NULL, NULL);
    if (x509 != NULL) {
      // TODO(ekasper): check that the issuing CA cert is temporally valid
      // and at least warn if it isn't.
      Cert* cert = new Cert(x509);
      string subject_name;
      CertVerifyResult is_trusted = IsTrusted(*cert, &subject_name);
      if (is_trusted != OK && is_trusted != ROOT_NOT_IN_LOCAL_STORE) {
        delete cert;
        error = true;
        break;
      }

      ++cert_count;
      if (is_trusted == OK) {
        delete cert;
      } else {
        certs_to_add.push_back(make_pair(subject_name, cert));
      }
    } else {
      // See if we reached the end of the file.
      auto err = ERR_peek_last_error();
      if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
          ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
        ClearOpenSSLErrors();
        break;
      } else {
        // A real error.
        LOG(ERROR) << "Badly encoded certificate file.";
        LOG_OPENSSL_ERRORS(WARNING);
        error = true;
        break;
      }
    }
  }

  BIO_free(bio_in);

  if (error || !cert_count) {
    while (!certs_to_add.empty()) {
      delete certs_to_add.back().second;
      certs_to_add.pop_back();
    }
    return false;
  }

  size_t new_certs = certs_to_add.size();
  while (!certs_to_add.empty()) {
    trusted_.insert(certs_to_add.back());
    certs_to_add.pop_back();
  }
  LOG(INFO) << "Added " << new_certs << " new certificate(s) to trusted store";

  return true;
}

void CertChecker::ClearAllTrustedCertificates() {
  std::multimap<string, const Cert*>::iterator it = trusted_.begin();
  for (; it != trusted_.end(); ++it) delete it->second;
  trusted_.clear();
}

CertChecker::CertVerifyResult CertChecker::CheckCertChain(
    CertChain* chain) const {
  if (chain == NULL || !chain->IsLoaded()) return INVALID_CERTIFICATE_CHAIN;

  // Weed out things that should obviously be precert chains instead.
  Cert::Status status =
      chain->LeafCert()->HasCriticalExtension(cert_trans::NID_ctPoison);
  if (status != Cert::TRUE && status != Cert::FALSE) {
    return CertChecker::INTERNAL_ERROR;
  }
  if (status == Cert::TRUE) return PRECERT_EXTENSION_IN_CERT_CHAIN;

  return CheckIssuerChain(chain);
}

CertChecker::CertVerifyResult CertChecker::CheckIssuerChain(
    CertChain* chain) const {
  if (chain->RemoveCertsAfterFirstSelfSigned() != Cert::TRUE) {
    LOG(ERROR) << "Failed to trim chain";
    return INTERNAL_ERROR;
  }

  // Note that it is OK to allow a root cert that is not CA:true
  // because we will later check that it is trusted.
  Cert::Status status = chain->IsValidCaIssuerChainMaybeLegacyRoot();
  if (status == Cert::FALSE) return INVALID_CERTIFICATE_CHAIN;
  if (status != Cert::TRUE) {
    LOG(ERROR) << "Failed to check issuer chain";
    return INTERNAL_ERROR;
  }

  status = chain->IsValidSignatureChain();
  if (status == Cert::UNSUPPORTED_ALGORITHM) {
    // UNSUPPORTED_ALGORITHM can happen when a weak algorithm (such as MD2)
    // is intentionally not accepted in which case it's correct to say that
    // the chain is invalid.
    // It can also happen when EVP is not properly initialized, in which case
    // it's more of an INTERNAL_ERROR. However a bust setup would manifest
    // itself in many other ways, including failing tests, so we assume the
    // failure is intentional.
    return UNSUPPORTED_ALGORITHM_IN_CERT_CHAIN;
  }
  if (status == Cert::FALSE) return INVALID_CERTIFICATE_CHAIN;

  if (status != Cert::TRUE) {
    LOG(ERROR) << "Failed to check signature chain";
    return INTERNAL_ERROR;
  }
  return GetTrustedCa(chain);
}

CertChecker::CertVerifyResult CertChecker::CheckPreCertChain(
    PreCertChain* chain, string* issuer_key_hash,
    string* tbs_certificate) const {
  if (chain == NULL || !chain->IsLoaded()) return INVALID_CERTIFICATE_CHAIN;
  Cert::Status status = chain->IsWellFormed();
  if (status == Cert::FALSE) return PRECERT_CHAIN_NOT_WELL_FORMED;
  if (status != Cert::TRUE) {
    LOG(ERROR) << "Failed to check precert chain format";
    return INTERNAL_ERROR;
  }
  // Check the issuer and signature chain.
  // We do not, at this point, concern ourselves with whether the CA
  // certificate that issued the precert is a Precertificate Signing
  // Certificate (i.e., has restricted Extended Key Usage) or not,
  // since this does not influence the validity of the chain. The
  // purpose of the EKU is effectively to allow CAs to create an
  // intermediate whose scope can be limited to CT precerts only (by
  // making this extension critical).
  // TODO(ekasper): determine (i.e., ask CAs) if CA:false
  // Precertificate Signing Certificates should be tolerated if they
  // have the necessary EKU set.
  // Preference is "no".
  CertVerifyResult res = CheckIssuerChain(chain);
  if (res != OK) return res;

  Cert::Status uses_pre_issuer = chain->UsesPrecertSigningCertificate();
  if (uses_pre_issuer != Cert::TRUE && uses_pre_issuer != Cert::FALSE)
    return INTERNAL_ERROR;

  string key_hash;
  if (uses_pre_issuer == Cert::TRUE) {
    if (chain->Length() < 3 ||
        chain->CertAt(2)->SPKISha256Digest(&key_hash) != Cert::TRUE)
      return INTERNAL_ERROR;
  } else if (chain->Length() < 2 ||
             chain->CertAt(1)->SPKISha256Digest(&key_hash) != Cert::TRUE) {
    return INTERNAL_ERROR;
  }
  // A well-formed chain always has a precert.
  TbsCertificate tbs(*chain->PreCert());
  if (!tbs.IsLoaded() ||
      tbs.DeleteExtension(cert_trans::NID_ctPoison) != Cert::TRUE)
    return INTERNAL_ERROR;

  // If the issuing cert is the special Precert Signing Certificate,
  // replace the issuer with the one that will sign the final cert.
  // Should always succeed as we've already verified that the chain
  // is well-formed.
  if (uses_pre_issuer == Cert::TRUE &&
      tbs.CopyIssuerFrom(*chain->PrecertIssuingCert()) != Cert::TRUE)
    return INTERNAL_ERROR;

  string der_tbs;
  if (tbs.DerEncoding(&der_tbs) != Cert::TRUE) return INTERNAL_ERROR;

  issuer_key_hash->assign(key_hash);
  tbs_certificate->assign(der_tbs);
  return OK;
}

CertChecker::CertVerifyResult CertChecker::GetTrustedCa(
    CertChain* chain) const {
  const Cert* subject = chain->LastCert();
  if (subject == NULL || !subject->IsLoaded()) {
    LOG(ERROR) << "Chain has no valid certs";
    return INTERNAL_ERROR;
  }

  // Look up issuer from the trusted store.
  if (trusted_.empty()) {
    LOG(WARNING) << "No trusted certificates loaded";
    return ROOT_NOT_IN_LOCAL_STORE;
  }

  string subject_name;
  CertVerifyResult is_trusted = IsTrusted(*subject, &subject_name);
  // Either an error, or OK, meaning the last cert is in our trusted store.
  // Note the trusted cert need not necessarily be self-signed.
  if (is_trusted != ROOT_NOT_IN_LOCAL_STORE) return is_trusted;

  string issuer_name;
  Cert::Status status = subject->DerEncodedIssuerName(&issuer_name);
  if (status == Cert::ERROR)
    return INTERNAL_ERROR;
  else if (status != Cert::TRUE)
    return INVALID_CERTIFICATE_CHAIN;

  if (subject_name == issuer_name) {
    // Self-signed: no need to scan again.
    return ROOT_NOT_IN_LOCAL_STORE;
  }

  std::pair<std::multimap<string, const Cert*>::const_iterator,
            std::multimap<string, const Cert*>::const_iterator> issuer_range =
      trusted_.equal_range(issuer_name);

  const Cert* issuer = NULL;
  for (std::multimap<string, const Cert*>::const_iterator it =
           issuer_range.first;
       it != issuer_range.second; ++it) {
    const Cert* issuer_cand = it->second;

    Cert::Status ok = subject->IsSignedBy(*issuer_cand);
    if (ok == Cert::UNSUPPORTED_ALGORITHM) {
      // If the cert's algorithm is unsupported, then there's no point
      // continuing: it's unconditionally invalid.
      return UNSUPPORTED_ALGORITHM_IN_CERT_CHAIN;
    }
    if (ok != Cert::TRUE && ok != Cert::FALSE) {
      LOG(ERROR) << "Failed to check signature for trusted root";
      return INTERNAL_ERROR;
    }
    if (ok == Cert::TRUE) {
      issuer = issuer_cand;
      break;
    }
  }

  if (issuer == NULL) return ROOT_NOT_IN_LOCAL_STORE;

  // Clone creates a new Cert but AddCert takes ownership even if Clone
  // failed and the cert can't be added, so we don't have to explicitly
  // check for IsLoaded here.
  if (chain->AddCert(issuer->Clone()) != Cert::TRUE) {
    LOG(ERROR) << "Failed to add trusted root to chain";
    return INTERNAL_ERROR;
  }

  return OK;
}

CertChecker::CertVerifyResult CertChecker::IsTrusted(
    const Cert& cert, string* subject_name) const {
  string cert_name;
  Cert::Status status = cert.DerEncodedSubjectName(&cert_name);
  if (status == Cert::ERROR)
    return INTERNAL_ERROR;
  else if (status != Cert::TRUE)
    return INVALID_CERTIFICATE_CHAIN;

  *subject_name = cert_name;

  std::pair<std::multimap<string, const Cert*>::const_iterator,
            std::multimap<string, const Cert*>::const_iterator> cand_range =
      trusted_.equal_range(cert_name);
  for (std::multimap<string, const Cert*>::const_iterator it = cand_range.first;
       it != cand_range.second; ++it) {
    const Cert* cand = it->second;
    Cert::Status matches = cert.IsIdenticalTo(*cand);
    if (matches != Cert::TRUE && matches != Cert::FALSE) {
      LOG(ERROR) << "Cert comparison failed";
      return INTERNAL_ERROR;
    }
    if (matches == Cert::TRUE) {
      return OK;
    }
  }
  return ROOT_NOT_IN_LOCAL_STORE;
}

Cert::Status CertChecker::IsCmsSignedByCert(CMS_ContentInfo* const cms,
                                            const Cert& cert) const {
  if (!cert.IsLoaded()) {
    LOG(ERROR) << "Can't check cert signer as it's not loaded";
    return Cert::ERROR;
  }

  // This stack must not be freed as it points into the CMS structure
  STACK_OF(CMS_SignerInfo) * const signers(CMS_get0_SignerInfos(cms));

  if (signers) {
    for (int s = 0; s < sk_CMS_SignerInfo_num(signers); ++s) {
      CMS_SignerInfo* const signer = sk_CMS_SignerInfo_value(signers, s);

      if (CMS_SignerInfo_cert_cmp(signer, cert.x509_) == 0) {
        return Cert::TRUE;
      }
    }
  }

  return Cert::FALSE;
}


Cert::Status CertChecker::UnpackCmsDerBio(BIO* cms_bio_in,
                                          const CertChain& certChain,
                                          BIO* cms_bio_out) {
  const Cert* subject = certChain.LastCert();
  if (!subject || !subject->IsLoaded()) {
    LOG(ERROR) << "Chain has no valid certs";
    return Cert::ERROR;
  }

  CMS_ContentInfo* const cms_content_info = d2i_CMS_bio(cms_bio_in, nullptr);

  if (!cms_content_info) {
    LOG(ERROR) << "Could not parse CMS data";
    LOG_OPENSSL_ERRORS(WARNING);
    return Cert::ERROR;
  }

  const ASN1_OBJECT* message_content_type(
      CMS_get0_eContentType(cms_content_info));
  int content_type_nid = OBJ_obj2nid(message_content_type);
  // TODO: Enforce content type here. This is not yet defined in the RFC.
  if (content_type_nid != NID_ctV2CmsPayloadContentType) {
    LOG(WARNING) << "CMS message content has unexpected type: "
                 << content_type_nid;
  }

  // Convert the validation chain to a certificate stack that can be used with
  // CMS_verify.
  STACK_OF(X509)* validation_chain = sk_X509_new(nullptr);

  for (int certNum = 0; certNum < certChain.Length(); ++certNum) {
    sk_X509_push(validation_chain, certChain.CertAt(certNum)->x509_);
  }

  // Must set CMS_NOINTERN as the RFC says certs SHOULD be omitted from the
  // message but the client might not have obeyed this. CMS_BINARY is required
  // to avoid MIME-related translation. CMS_NO_SIGNER_CERT_VERIFY because we
  // will do our own checks that the chain is valid and the message may not
  // be signed directly by a trusted cert. We don't check it's a signed data
  // object CMS type as OpenSSL does this.
  int verified = CMS_verify(cms_content_info, validation_chain, nullptr,
                            nullptr, cms_bio_out,
                            CMS_NO_SIGNER_CERT_VERIFY | CMS_NOINTERN
                            | CMS_BINARY);

  sk_X509_free(validation_chain);

  CMS_ContentInfo_free(cms_content_info);

  return (verified == 1) ? Cert::TRUE : Cert::FALSE;
}

Cert* CertChecker::UnpackCmsSignedCertificate(BIO* cms_bio_in,
                                              const CertChain& certChain) {
  BIO* unpacked_bio = BIO_new(BIO_s_mem());
  Cert* const cert = new Cert();

  if (UnpackCmsDerBio(cms_bio_in, certChain, unpacked_bio) == Cert::TRUE) {
    // The unpacked data should be a valid DER certificate.
    // TODO: The RFC does not yet define this as the format so this may
    // need to change.
    Cert::Status status = cert->LoadFromDerBio(unpacked_bio);

    if (status != Cert::TRUE) {
      LOG(WARNING) << "Could not unpack cert from CMS DER encoded data";
    }
  } else {
    LOG_OPENSSL_ERRORS(ERROR);
  }

  BIO_free(cms_bio_in);
  BIO_free(unpacked_bio);

  return cert;
}

}  // namespace cert_trans
