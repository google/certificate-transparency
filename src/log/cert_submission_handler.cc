#include <glog/logging.h>
#include <string>

#include "log/cert.h"
#include "log/cert_checker.h"
#include "log/cert_submission_handler.h"
#include "log/ct_extensions.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"

using ct::LogEntry;
using ct::PrecertChainEntry;
using ct::X509ChainEntry;
using std::string;

using ct::Cert;
using ct::CertChain;
using ct::CertChecker;
using ct::PreCertChain;
using ct::TbsCertificate;

// TODO(ekasper): handle Cert errors consistently and log some errors here
// if they fail.
CertSubmissionHandler::CertSubmissionHandler(CertChecker *cert_checker)
    : cert_checker_(cert_checker) {}

CertSubmissionHandler::SubmitResult
CertSubmissionHandler::ProcessSubmission(const string &submission,
                                         LogEntry *entry) {
  CHECK_NOTNULL(entry);
  CHECK(entry->has_type());

  if (submission.empty())
    return EMPTY_SUBMISSION;

  SubmitResult submit_result = INVALID_TYPE;
  switch (entry->type()) {
    case ct::X509_ENTRY:
      submit_result = ProcessX509Submission(submission, entry);
      break;
    case ct::PRECERT_ENTRY:
      submit_result = ProcessPreCertSubmission(submission,  entry);
      break;
    default:
      // We support all types, so we should never get here if the caller sets
      // a valid type.
      LOG(FATAL) << "Unknown entry type " << entry->type();
      break;
  }

  if (submit_result != OK)
    return submit_result;

  Serializer::SerializeResult serialize_result =
      Serializer::CheckLogEntryFormat(*entry);
  if (serialize_result != Serializer::OK)
    return GetFormatError(serialize_result);

  return OK;
}

// static
bool
CertSubmissionHandler::X509ChainToEntry(const CertChain &chain,
                                        LogEntry *entry) {
  if (!chain.IsLoaded())
    return false;

  Cert::Status status = chain.LeafCert()->HasExtension(
      ct::NID_ctEmbeddedSignedCertificateTimestampList);
  if (status != Cert::TRUE && status != Cert::FALSE) {
    LOG(ERROR) << "Failed to check embedded SCT extension.";
    return false;
  }

  if (status == Cert::TRUE) {
    if (chain.Length() < 2) {
      // need issuer
      return false;
    }

    entry->set_type(ct::PRECERT_ENTRY);
    string key_hash;
    if (chain.CertAt(1)->SPKISha256Digest(&key_hash) != Cert::TRUE)
      return false;

    entry->mutable_precert_entry()->mutable_pre_cert()->set_issuer_key_hash(
        key_hash);

    string tbs;
    if (!SerializedTbs(*chain.LeafCert(), &tbs))
      return false;

    entry->mutable_precert_entry()->mutable_pre_cert()->
        set_tbs_certificate(tbs);
    return true;
  } else {
    entry->set_type(ct::X509_ENTRY);
    string der_cert;
    if (chain.LeafCert()->DerEncoding(&der_cert) != Cert::TRUE)
      return false;

    entry->mutable_x509_entry()->set_leaf_certificate(der_cert);
    return true;
  }
}

CertSubmissionHandler::SubmitResult
CertSubmissionHandler::ProcessX509Submission(CertChain *chain,
                                             LogEntry *entry) {
  CertChecker::CertVerifyResult result = cert_checker_->CheckCertChain(chain);
  if (result != CertChecker::OK)
    return GetVerifyError(result);

  // We have a valid chain; make the entry.
  string der_cert;
  // Nothing should fail anymore as we have validated the chain.
  if (chain->LeafCert()->DerEncoding(&der_cert) != Cert::TRUE)
    return INTERNAL_ERROR;

  X509ChainEntry *x509_entry = entry->mutable_x509_entry();
  x509_entry->set_leaf_certificate(der_cert);
  for (size_t i = 1; i < chain->Length(); ++i) {
    if (chain->CertAt(i)->DerEncoding(&der_cert) != Cert::TRUE)
      return INTERNAL_ERROR;
    x509_entry->add_certificate_chain(der_cert);
  }
  entry->set_type(ct::X509_ENTRY);
  return OK;
}

// Inputs must be concatenated PEM entries.
// Format checking is done in the parent class.
CertSubmissionHandler::SubmitResult
CertSubmissionHandler::ProcessX509Submission(const string &submission,
                                             LogEntry *entry) {
  string pem_string(reinterpret_cast<const char*>(submission.data()),
                    submission.size());
  CertChain chain(pem_string);

  if (!chain.IsLoaded())
    return INVALID_PEM_ENCODED_CHAIN;

  return ProcessX509Submission(&chain, entry);
}

CertSubmissionHandler::SubmitResult
CertSubmissionHandler::ProcessPreCertSubmission(const string &submission,
                                                LogEntry *entry) {
  string pem_string(reinterpret_cast<const char*>(submission.data()),
                    submission.size());
  PreCertChain chain(pem_string);
  if (!chain.IsLoaded())
    return INVALID_PEM_ENCODED_CHAIN;

  return ProcessPreCertSubmission(&chain, entry);
}

CertSubmissionHandler::SubmitResult
CertSubmissionHandler::ProcessPreCertSubmission(PreCertChain *chain,
                                                LogEntry *entry) {
  PrecertChainEntry *precert_entry = entry->mutable_precert_entry();
  CertChecker::CertVerifyResult result = cert_checker_->CheckPreCertChain(
      chain, precert_entry->mutable_pre_cert()->mutable_issuer_key_hash(),
      precert_entry->mutable_pre_cert()->mutable_tbs_certificate());

  if (result != CertChecker::OK)
    return GetVerifyError(result);

  // We have a valid chain; make the entry.
  string der_cert;
  // Nothing should fail anymore as we have validated the chain.
  if (chain->LeafCert()->DerEncoding(&der_cert) != Cert::TRUE)
    return INTERNAL_ERROR;
  precert_entry->set_pre_certificate(der_cert);
  for (size_t i = 1; i < chain->Length(); ++i) {
    if (chain->CertAt(i)->DerEncoding(&der_cert) != Cert::TRUE)
      return INTERNAL_ERROR;
    precert_entry->add_precertificate_chain(der_cert);
  }

  return OK;
}

// static
bool CertSubmissionHandler::SerializedTbs(const Cert &cert, string *result) {
  if (!cert.IsLoaded())
    return false;

  Cert::Status status = cert.HasExtension(
      ct::NID_ctEmbeddedSignedCertificateTimestampList);
  if (status != Cert::TRUE && status != Cert::FALSE)
    return false;

  // Delete the embedded proof.
  TbsCertificate tbs(cert);
  if (!tbs.IsLoaded())
    return false;

  if (status == Cert::TRUE &&
      tbs.DeleteExtension(ct::NID_ctEmbeddedSignedCertificateTimestampList) !=
      Cert::TRUE)
    return false;

  string der_tbs;
  if (tbs.DerEncoding(&der_tbs) != Cert::TRUE)
    return false;
  result->assign(der_tbs);
  return true;
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
    case CertChecker::INTERNAL_ERROR:
      submit_result = INTERNAL_ERROR;
      break;
    case CertChecker::PRECERT_EXTENSION_IN_CERT_CHAIN:
      submit_result = INVALID_CERTIFICATE_CHAIN;
      break;
    default:
      LOG(FATAL) << "Unknown CertChecker error " << result;
  }
  return submit_result;
}
