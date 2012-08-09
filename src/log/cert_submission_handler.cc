#include <assert.h>
#include <string>

#include "../include/types.h"
#include "../proto/ct.pb.h"
#include "../proto/serializer.h"
#include "cert.h"
#include "cert_checker.h"
#include "cert_submission_handler.h"

CertSubmissionHandler::CertSubmissionHandler(CertChecker *cert_checker)
    : cert_checker_(cert_checker) {
  assert(cert_checker_ != NULL);
}

// static
CertificateEntry
*CertSubmissionHandler::X509ChainToEntry(const CertChain &chain) {
  if (!chain.IsLoaded())
    return NULL;
  CertificateEntry *entry = new CertificateEntry();
  if (chain.LeafCert()->HasExtension(Cert::kEmbeddedProofExtensionOID)) {
    entry->set_type(CertificateEntry::PRECERT_ENTRY);
    entry->set_leaf_certificate(TbsCertificate(chain));
  } else {
    entry->set_type(CertificateEntry::X509_ENTRY);
    entry->set_leaf_certificate(chain.LeafCert()->DerEncoding());
  }

  if (!Serializer::CheckSignedFormat(*entry)) {
    delete entry;
    return NULL;
  }

  return entry;
}

// Inputs must be concatenated PEM entries.
// Format checking is done in the parent class.
bool CertSubmissionHandler::ProcessX509Submission(const bstring &submission,
                                                  CertificateEntry *entry) {
  std::string pem_string(reinterpret_cast<const char*>(submission.data()),
                         submission.size());
  CertChain chain(pem_string);

  if (!chain.IsLoaded() || !cert_checker_->CheckCertChain(chain))
    return false;

  // We have a valid chain; make the entry.
  entry->set_leaf_certificate(chain.LeafCert()->DerEncoding());
  for (size_t i = 1; i < chain.Length(); ++i)
    entry->add_intermediates(chain.CertAt(i)->DerEncoding());
  return true;
}

bool CertSubmissionHandler::ProcessPreCertSubmission(const bstring &submission,
                                                     CertificateEntry *entry) {
  std::string pem_string(reinterpret_cast<const char*>(submission.data()),
                         submission.size());
  PreCertChain chain(pem_string);
  if (!chain.IsLoaded() || !cert_checker_->CheckPreCertChain(chain))
    return false;

  // We have a valid chain; make the entry.
  entry->set_leaf_certificate(TbsCertificate(chain));
  entry->add_intermediates(chain.PreCert()->DerEncoding());
  entry->add_intermediates(chain.CaPreCert()->DerEncoding());
  for (size_t i = 0; i < chain.IntermediateLength(); ++i)
    entry->add_intermediates(chain.IntermediateAt(i)->DerEncoding());
  return true;
}

bstring CertSubmissionHandler::TbsCertificate(const PreCertChain &chain) {
  if (!chain.IsLoaded() || !chain.IsWellFormed())
    return bstring();

  Cert *tbs = chain.PreCert()->Clone();
  assert(tbs != NULL && tbs->IsLoaded());

  // Remove the poison extension and the signature.
  tbs->DeleteExtension(Cert::kPoisonExtensionOID);
  tbs->DeleteSignature();

  // Fix the issuer.
  const Cert *ca_precert = chain.CaPreCert();
  assert(ca_precert != NULL && ca_precert->IsLoaded());
  tbs->CopyIssuerFrom(*ca_precert);

  bstring der_cert = tbs->DerEncoding();
  delete tbs;
  return der_cert;
}

bstring CertSubmissionHandler::TbsCertificate(const CertChain &chain) {
  if (!chain.IsLoaded())
    return bstring();

  const Cert *leaf = chain.LeafCert();
  assert(leaf != NULL && leaf->IsLoaded());

  Cert *tbs = leaf->Clone();

  // Delete the signature and the embedded proof.
  tbs->DeleteExtension(Cert::kEmbeddedProofExtensionOID);
  tbs->DeleteSignature();

  bstring der_cert = tbs->DerEncoding();
  delete tbs;
  return der_cert;
}
