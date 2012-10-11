#include <glog/logging.h>
#include <string>

#include "cert.h"
#include "cert_checker.h"
#include "cert_submission_handler.h"
#include "ct.pb.h"
#include "serializer.h"

using ct::CertificateEntry;
using std::string;

CertSubmissionHandler::CertSubmissionHandler(CertChecker *cert_checker)
    : cert_checker_(cert_checker) {}

CertSubmissionHandler::SubmitResult
CertSubmissionHandler::ProcessSubmission(const string &submission,
                                         CertificateEntry *entry) {
  CHECK_NOTNULL(entry);
  CHECK(entry->has_type());

  if (submission.empty())
    return EMPTY_SUBMISSION;

  SubmitResult submit_result = INVALID_TYPE;
  switch (entry->type()) {
    case CertificateEntry::X509_ENTRY:
      submit_result = ProcessX509Submission(submission, entry);
      break;
    case CertificateEntry::PRECERT_ENTRY:
      submit_result = ProcessPreCertSubmission(submission, entry);
      break;
    default:
      // We support all types, so we should currently never get here.
      LOG(FATAL) << "Unknown entry type " << entry->type();
      break;
  }

  if (submit_result != OK)
    return submit_result;

  Serializer::SerializeResult serialize_result =
      Serializer::CheckFormat(*entry);
  if (serialize_result != Serializer::OK)
    return GetFormatError(serialize_result);

  return OK;
}

// static
CertSubmissionHandler::SubmitResult
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
CertSubmissionHandler::SubmitResult
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

CertSubmissionHandler::SubmitResult
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
  CHECK_NOTNULL(tbs);
  CHECK(tbs->IsLoaded());

  // Remove the poison extension and the signature.
  tbs->DeleteExtension(Cert::kPoisonExtensionOID);
  tbs->DeleteSignature();

  // Fix the issuer.
  const Cert *ca_precert = chain.CaPreCert();
  CHECK_NOTNULL(ca_precert);
  CHECK(ca_precert->IsLoaded());
  tbs->CopyIssuerFrom(*ca_precert);

  string der_cert = tbs->DerEncoding();
  delete tbs;
  return der_cert;
}

string CertSubmissionHandler::TbsCertificate(const CertChain &chain) {
  if (!chain.IsLoaded())
    return string();

  const Cert *leaf = chain.LeafCert();
  CHECK_NOTNULL(leaf);
  CHECK(leaf->IsLoaded());

  Cert *tbs = leaf->Clone();

  // Delete the signature and the embedded proof.
  tbs->DeleteExtension(Cert::kEmbeddedProofExtensionOID);
  tbs->DeleteSignature();

  string der_cert = tbs->DerEncoding();
  delete tbs;
  return der_cert;
}

// static
CertSubmissionHandler::SubmitResult
CertSubmissionHandler::GetFormatError(Serializer::SerializeResult result) {
  SubmitResult submit_result;
  switch (result) {
    // Since the submission handler checks that the submission is valid
    // for a given type, the only error we should be seeing here
    // is a chain whose canonical encoding is too long.
    // Anything else (invalid/empty certs) should be caught earlier.
    case Serializer::CERTIFICATE_TOO_LONG:
    case Serializer::CERTIFICATE_CHAIN_TOO_LONG:
      submit_result = SUBMISSION_TOO_LONG;
      break;
    default:
      LOG(FATAL) << "Unknown Serializer error " << result;
  }

  return submit_result;
}

// static
CertSubmissionHandler::SubmitResult
CertSubmissionHandler::GetVerifyError(CertChecker::CertVerifyResult result) {
  SubmitResult submit_result;
  switch (result) {
    case CertChecker::INVALID_CERTIFICATE_CHAIN:
      submit_result = INVALID_CERTIFICATE_CHAIN;
      break;
    case CertChecker::PRECERT_CHAIN_NOT_WELL_FORMED:
      submit_result = PRECERT_CHAIN_NOT_WELL_FORMED;
      break;
    case CertChecker::ROOT_NOT_IN_LOCAL_STORE:
      submit_result = UNKNOWN_ROOT;
      break;
    default:
      LOG(FATAL) << "Unknown CertChecker error " << result;
  }
  return submit_result;
}
