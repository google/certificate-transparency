/* -*- indent-tabs-mode: nil -*- */
#include "log/cert_checker.h"

#include <glog/logging.h>
#include <memory>
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
using std::unique_ptr;
using std::vector;
using util::ClearOpenSSLErrors;
using util::Status;
using util::StatusOr;
using util::error::Code;

namespace cert_trans {

CertChecker::~CertChecker() {
  ClearAllTrustedCertificates();
}

bool CertChecker::LoadTrustedCertificates(const string& cert_file) {
  // A read-only BIO.
  BIO* bio_in = BIO_new(BIO_s_file());
  if (!bio_in) {
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
      -1  /* no length, since null-terminated */);
  if (!bio_in) {
    LOG_OPENSSL_ERRORS(ERROR);
    return false;
  }

  return LoadTrustedCertificatesFromBIO(bio_in);
}

bool CertChecker::LoadTrustedCertificatesFromBIO(BIO* bio_in) {
  CHECK_NOTNULL(bio_in);
  std::vector<std::pair<string, Cert*> > certs_to_add;
  bool error = false;
  // certs_to_add may be empty if no new certs were added, so keep track of
  // successfully parsed cert count separately.
  size_t cert_count = 0;

  while (!error) {
    X509* x509 = PEM_read_bio_X509(bio_in, nullptr, nullptr, nullptr);
    if (x509) {
      // TODO(ekasper): check that the issuing CA cert is temporally valid
      // and at least warn if it isn't.
      unique_ptr<Cert> cert(new Cert(x509));
      string subject_name;
      const StatusOr<bool> is_trusted(IsTrusted(*cert, &subject_name));
      if (!is_trusted.ok()) {
        error = true;
        break;
      }

      ++cert_count;
      if (!is_trusted.ValueOrDie()) {
        certs_to_add.push_back(make_pair(subject_name, cert.release()));
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
  for (; it != trusted_.end(); ++it) {
    delete it->second;
  }
  trusted_.clear();
}

Status CertChecker::CheckCertChain(CertChain* chain) const {
  if (!chain || !chain->IsLoaded())
    return Status(util::error::INVALID_ARGUMENT, "invalid certificate chain");

  // Weed out things that should obviously be precert chains instead.
  const StatusOr<bool> has_poison =
      chain->LeafCert()->HasCriticalExtension(cert_trans::NID_ctPoison);
  if (!has_poison.ok()) {
    return Status(util::error::INTERNAL, "internal error");
  }
  if (has_poison.ValueOrDie()) {
    return Status(util::error::INVALID_ARGUMENT,
                  "precert extension in certificate chain");
  }

  return CheckIssuerChain(chain);
}

Status CertChecker::CheckIssuerChain(CertChain* chain) const {
  if (!chain->RemoveCertsAfterFirstSelfSigned()) {
    LOG(ERROR) << "Failed to trim chain";
    return Status(util::error::INTERNAL, "failed to trim chain");
  }

  // Note that it is OK to allow a root cert that is not CA:true
  // because we will later check that it is trusted.
  Status status = chain->IsValidCaIssuerChainMaybeLegacyRoot();
  if (!status.ok()) {
    LOG(ERROR) << "Failed to check issuer chain";
    return Status(status.CanonicalCode(), "invalid certificate chain");
  }

  const Status valid_chain(chain->IsValidSignatureChain());
  if (!valid_chain.ok()) {
    return valid_chain;
  }

  return GetTrustedCa(chain);
}

Status CertChecker::CheckPreCertChain(PreCertChain* chain,
                                      string* issuer_key_hash,
                                      string* tbs_certificate) const {
  if (!chain || !chain->IsLoaded()) {
    return Status(util::error::INVALID_ARGUMENT, "invalid certificate chain");
  }

  const StatusOr<bool> chain_well_formed(chain->IsWellFormed());
  if (chain_well_formed.ok() && !chain_well_formed.ValueOrDie()) {
    return Status(util::error::INVALID_ARGUMENT, "prechain not well formed");
  }
  if (!chain_well_formed.ok()) {
    LOG(ERROR) << "Failed to check precert chain format";
    return Status(util::error::INTERNAL, "internal error");
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

  // TODO(pphaneuf): Once Cert::IsWellFormed returns a util::Status,
  // remove the braces and re-use the one above.
  {
    Status status(CheckIssuerChain(chain));
    if (!status.ok())
      return status;
  }

  const StatusOr<bool> uses_pre_issuer = chain->UsesPrecertSigningCertificate();
  if (!uses_pre_issuer.ok()) {
    return Status(util::error::INTERNAL, "internal error");
  }

  string key_hash;
  if (uses_pre_issuer.ValueOrDie()) {
    if (chain->Length() < 3 ||
        chain->CertAt(2)->SPKISha256Digest(&key_hash) != util::Status::OK)
      return Status(util::error::INTERNAL, "internal error");
  } else if (chain->Length() < 2 ||
             chain->CertAt(1)->SPKISha256Digest(&key_hash) !=
                 util::Status::OK) {
    return Status(util::error::INTERNAL, "internal error");
  }
  // A well-formed chain always has a precert.
  TbsCertificate tbs(*chain->PreCert());
  if (!tbs.IsLoaded() ||
      !tbs.DeleteExtension(cert_trans::NID_ctPoison).ok()) {
    return Status(util::error::INTERNAL, "internal error");
  }

  // If the issuing cert is the special Precert Signing Certificate,
  // replace the issuer with the one that will sign the final cert.
  // Should always succeed as we've already verified that the chain
  // is well-formed.
  if (uses_pre_issuer.ValueOrDie() &&
      !tbs.CopyIssuerFrom(*chain->PrecertIssuingCert()).ok()) {
    return Status(util::error::INTERNAL, "internal error");
  }

  string der_tbs;
  if (!tbs.DerEncoding(&der_tbs).ok()) {
    return Status(util::error::INTERNAL,
                  "could not DER-encode tbs certificate");
  }

  issuer_key_hash->assign(key_hash);
  tbs_certificate->assign(der_tbs);
  return Status::OK;
}

Status CertChecker::GetTrustedCa(CertChain* chain) const {
  const Cert* subject = chain->LastCert();
  if (!subject || !subject->IsLoaded()) {
    LOG(ERROR) << "Chain has no valid certs";
    return Status(util::error::INTERNAL, "chain has no valid certificate");
  }

  // Look up issuer from the trusted store.
  if (trusted_.empty()) {
    LOG(WARNING) << "No trusted certificates loaded";
    return Status(util::error::FAILED_PRECONDITION,
                  "no trusted certificates loaded");
  }

  string subject_name;
  const StatusOr<bool> is_trusted(IsTrusted(*subject, &subject_name));
  // Either an error, or true, meaning the last cert is in our trusted
  // store.  Note the trusted cert need not necessarily be
  // self-signed.
  if (!is_trusted.ok() || is_trusted.ValueOrDie())
    return is_trusted.status();

  string issuer_name;
  util::Status status = subject->DerEncodedIssuerName(&issuer_name);
  if (status != util::Status::OK) {
    // Doesn't matter whether the extension doesn't or exist or is corrupt,
    // it's still a bad chain
    return Status(util::error::INVALID_ARGUMENT, "invalid certificate chain");
  }

  if (subject_name == issuer_name) {
    // Self-signed: no need to scan again.
    return Status(util::error::FAILED_PRECONDITION,
                  "untrusted self-signed certificate");
  }

  std::pair<std::multimap<string, const Cert*>::const_iterator,
            std::multimap<string, const Cert*>::const_iterator> issuer_range =
      trusted_.equal_range(issuer_name);

  const Cert* issuer(nullptr);
  for (std::multimap<string, const Cert*>::const_iterator it =
           issuer_range.first;
       it != issuer_range.second; ++it) {
    const Cert* issuer_cand = it->second;

    StatusOr<bool> signed_by_issuer = subject->IsSignedBy(*issuer_cand);
    if (signed_by_issuer.status().CanonicalCode() == Code::UNIMPLEMENTED) {
      // If the cert's algorithm is unsupported, then there's no point
      // continuing: it's unconditionally invalid.
      return Status(util::error::INVALID_ARGUMENT,
                    "unsupported algorithm in certificate chain");
    }
    if (!signed_by_issuer.ok()) {
      LOG(ERROR) << "Failed to check signature for trusted root";
      return Status(util::error::INTERNAL,
                    "failed to check signature for trusted root");
    }
    if (signed_by_issuer.ValueOrDie()) {
      issuer = issuer_cand;
      break;
    }
  }

  if (!issuer) {
    return Status(util::error::FAILED_PRECONDITION, "unknown root");
  }

  // Clone creates a new Cert but AddCert takes ownership even if Clone
  // failed and the cert can't be added, so we don't have to explicitly
  // check for IsLoaded here.
  if (!chain->AddCert(issuer->Clone())) {
    LOG(ERROR) << "Failed to add trusted root to chain";
    return Status(util::error::INTERNAL,
                  "failed to add trusted root to chain");
  }

  return Status::OK;
}

StatusOr<bool> CertChecker::IsTrusted(const Cert& cert,
                                      string* subject_name) const {
  string cert_name;
  util::Status status = cert.DerEncodedSubjectName(&cert_name);
  if (status != util::Status::OK) {
    // Doesn't matter whether it failed to decode or did not exist
    return Status(util::error::INVALID_ARGUMENT, "invalid certificate chain");
  }

  *subject_name = cert_name;

  std::pair<std::multimap<string, const Cert*>::const_iterator,
            std::multimap<string, const Cert*>::const_iterator> cand_range =
      trusted_.equal_range(cert_name);
  for (std::multimap<string, const Cert*>::const_iterator it = cand_range.first;
       it != cand_range.second; ++it) {
    const Cert* cand = it->second;
    if (cert.IsIdenticalTo(*cand)) {
      return true;
    }
  }
  return false;
}

util::StatusOr<bool> CertChecker::IsCmsSignedByCert(CMS_ContentInfo* const cms,
                                                    const Cert& cert) const {
  CHECK_NOTNULL(cms);

  if (!cert.IsLoaded()) {
    LOG(ERROR) << "Can't check cert signer as it's not loaded";
    return Status(util::error::FAILED_PRECONDITION, "Cert not loaded");
  }

  // This stack must not be freed as it points into the CMS structure
  STACK_OF(CMS_SignerInfo)* const signers(CMS_get0_SignerInfos(cms));

  if (signers) {
    for (int s = 0; s < sk_CMS_SignerInfo_num(signers); ++s) {
      CMS_SignerInfo* const signer = sk_CMS_SignerInfo_value(signers, s);

      if (CMS_SignerInfo_cert_cmp(signer, cert.x509_) == 0) {
        return true;
      }
    }
  }

  return false;
}


util::Status CertChecker::UnpackCmsDerBio(BIO* cms_bio_in,
                                          const Cert& cert,
                                          BIO* cms_bio_out) {
  CHECK_NOTNULL(cms_bio_in);

  if (!cert.IsLoaded()) {
    LOG(ERROR) << "Cert for CMS verify not loaded";
    return Status(util::error::FAILED_PRECONDITION, "Cert not loaded");
  }

  CMS_ContentInfo* const cms_content_info = d2i_CMS_bio(cms_bio_in, nullptr);

  if (!cms_content_info) {
    LOG(ERROR) << "Could not parse CMS data";
    LOG_OPENSSL_ERRORS(WARNING);
    return Status(util::error::INVALID_ARGUMENT,
                  "CMS data could not be parsed");
  }

  const ASN1_OBJECT* message_content_type(
      CMS_get0_eContentType(cms_content_info));
  int content_type_nid = OBJ_obj2nid(message_content_type);
  // TODO: Enforce content type here. This is not yet defined in the RFC.
  if (content_type_nid != NID_ctV2CmsPayloadContentType) {
    LOG(WARNING) << "CMS message content has unexpected type: "
                 << content_type_nid;
  }

  // Create a certificate stack from our expected signing cert that can be used
  // by CMS_verify.
  STACK_OF(X509)* validation_chain = sk_X509_new(nullptr);

  sk_X509_push(validation_chain, cert.x509_);

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

  return (verified == 1) ? util::Status::OK
                         : util::Status(util::error::INVALID_ARGUMENT,
                                        "CMS verification failed");
}


Cert* CertChecker::UnpackCmsSignedCertificate(BIO* cms_bio_in,
                                              const Cert& verify_cert) {
  CHECK_NOTNULL(cms_bio_in);
  BIO* unpacked_bio = BIO_new(BIO_s_mem());
  unique_ptr<Cert> cert(new Cert());

  if (UnpackCmsDerBio(cms_bio_in, verify_cert, unpacked_bio).ok()) {
    // The unpacked data should be a valid DER certificate.
    // TODO: The RFC does not yet define this as the format so this may
    // need to change.
    util::Status status = cert->LoadFromDerBio(unpacked_bio);

    if (!status.ok()) {
      LOG(WARNING) << "Could not unpack cert from CMS DER encoded data";
    }
  } else {
    LOG_OPENSSL_ERRORS(ERROR);
  }

  BIO_free(unpacked_bio);

  return cert.release();
}

}  // namespace cert_trans
