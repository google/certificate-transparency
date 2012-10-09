#include <assert.h>
#include <string>

#include "cert.h"
#include "cert_checker.h"
#include "cert_submission_handler.h"
#include "ct.pb.h"
#include "serializer.h"

using ct::CertificateEntry;
using std::string;

CertSubmissionHandler::CertSubmissionHandler(CertChecker *cert_checker)
    : cert_checker_(cert_checker) {
  assert(cert_checker_ != NULL);
}

// static
SubmissionHandler::SubmitResult
CertSubmissionHandler::X509ChainToEntry(const CertChain &chain,
                                        CertificateEntry *entry) {
  if (!chain.IsLoaded())
    return CHAIN_NOT_LOADED;
  if (chain.LeafCert()->HasExtension(Cert::kEmbeddedProofExtensionOID)) {
    entry->set_type(CertificateEntry::PRECERT_ENTRY);
    entry->set_leaf_certificate(TbsCertificate(chain));
  } else {
    entry->set_type(CertificateEntry::X509_ENTRY);
    entry->set_leaf_certificate(chain.LeafCert()->DerEncoding());
  }

  Serializer::SerializeResult serialize_result =
      Serializer::CheckSignedFormat(*entry);
  if (serialize_result != Serializer::OK)
    return GetFormatError(serialize_result);

  return OK;
}

// Inputs must be concatenated PEM entries.
// Format checking is done in the parent class.
SubmissionHandler::SubmitResult
CertSubmissionHandler::ProcessX509Submission(const string &submission,
                                             CertificateEntry *entry) {
  string pem_string(reinterpret_cast<const char*>(submission.data()),
                         submission.size());
  CertChain chain(pem_string);

  if (!chain.IsLoaded())
    return INVALID_PEM_ENCODED_CHAIN;

  CertChecker::CertVerifyResult result = cert_checker_->CheckCertChain(chain);
  if (result != CertChecker::OK)
    return GetVerifyError(result);

  // We have a valid chain; make the entry.
  // TODO(ekasper): the trusted CA cert MAY be included in the submission.
  // Should we discard it?
  entry->set_leaf_certificate(chain.LeafCert()->DerEncoding());
  for (size_t i = 1; i < chain.Length(); ++i)
    entry->add_intermediates(chain.CertAt(i)->DerEncoding());
  return OK;
}

SubmissionHandler::SubmitResult
CertSubmissionHandler::ProcessPreCertSubmission(const string &submission,
                                                CertificateEntry *entry) {
  string pem_string(reinterpret_cast<const char*>(submission.data()),
                         submission.size());
  PreCertChain chain(pem_string);
  if (!chain.IsLoaded())
    return INVALID_PEM_ENCODED_CHAIN;

  CertChecker::CertVerifyResult result =
      cert_checker_->CheckPreCertChain(chain);
  if (result != CertChecker::OK)
    return GetVerifyError(result);

  // We have a valid chain; make the entry.
  entry->set_leaf_certificate(TbsCertificate(chain));
  entry->add_intermediates(chain.PreCert()->DerEncoding());
  entry->add_intermediates(chain.CaPreCert()->DerEncoding());
  for (size_t i = 0; i < chain.IntermediateLength(); ++i)
    entry->add_intermediates(chain.IntermediateAt(i)->DerEncoding());
  return OK;
}

string CertSubmissionHandler::TbsCertificate(const PreCertChain &chain) {
  if (!chain.IsLoaded() || !chain.IsWellFormed())
    return string();

  Cert *tbs = chain.PreCert()->Clone();
  assert(tbs != NULL && tbs->IsLoaded());

  // Remove the poison extension and the signature.
  tbs->DeleteExtension(Cert::kPoisonExtensionOID);
  tbs->DeleteSignature();

  // Fix the issuer.
  const Cert *ca_precert = chain.CaPreCert();
  assert(ca_precert != NULL && ca_precert->IsLoaded());
  tbs->CopyIssuerFrom(*ca_precert);

  string der_cert = tbs->DerEncoding();
  delete tbs;
  return der_cert;
}

string CertSubmissionHandler::TbsCertificate(const CertChain &chain) {
  if (!chain.IsLoaded())
    return string();

  const Cert *leaf = chain.LeafCert();
  assert(leaf != NULL && leaf->IsLoaded());

  Cert *tbs = leaf->Clone();

  // Delete the signature and the embedded proof.
  tbs->DeleteExtension(Cert::kEmbeddedProofExtensionOID);
  tbs->DeleteSignature();

  string der_cert = tbs->DerEncoding();
  delete tbs;
  return der_cert;
}
