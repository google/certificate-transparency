/* -*- indent-tabs-mode: nil -*- */
#include "log/frontend.h"

#include <glog/logging.h>

#include "log/cert.h"
#include "log/cert_submission_handler.h"
#include "log/frontend_signer.h"
#include "proto/ct.pb.h"

using cert_trans::CertChain;
using cert_trans::PreCertChain;
using ct::LogEntry;
using ct::SignedCertificateTimestamp;
using std::string;
using std::lock_guard;
using std::mutex;

Frontend::Frontend(CertSubmissionHandler* handler, FrontendSigner* signer)
    : handler_(handler), signer_(signer), stats_() {
}

Frontend::~Frontend() {
  delete signer_;
  delete handler_;
}

void Frontend::GetStats(Frontend::FrontendStats* stats) const {
  lock_guard<mutex> lock(stats_mutex_);
  *stats = stats_;
}

SubmitResult Frontend::QueueProcessedEntry(
    CertSubmissionHandler::SubmitResult pre_result, const LogEntry& entry,
    SignedCertificateTimestamp* sct) {
  if (pre_result != CertSubmissionHandler::OK) {
    SubmitResult result = GetSubmitError(pre_result);
    UpdateStats(entry.type(), result);
    return result;
  }

  // Step 2. Submit to database.
  FrontendSigner::SubmitResult signer_result = signer_->QueueEntry(entry, sct);

  SubmitResult result;
  switch (signer_result) {
    case FrontendSigner::NEW:
      result = ADDED;
      break;
    case FrontendSigner::DUPLICATE:
      result = DUPLICATE;
      break;
    default:
      LOG(FATAL) << "Unknown FrontendSigner return code " << signer_result;
  }

  UpdateStats(entry.type(), result);
  return result;
}

SubmitResult Frontend::QueueX509Entry(CertChain* chain,
                                      SignedCertificateTimestamp* sct) {
  LogEntry entry;
  // Make sure the correct statistics get updated in case of error.
  entry.set_type(ct::X509_ENTRY);
  return QueueProcessedEntry(handler_->ProcessX509Submission(chain, &entry),
                             entry, sct);
}

SubmitResult Frontend::QueuePreCertEntry(PreCertChain* chain,
                                         SignedCertificateTimestamp* sct) {
  LogEntry entry;
  // Make sure the correct statistics get updated in case of error.
  entry.set_type(ct::PRECERT_ENTRY);
  return QueueProcessedEntry(handler_->ProcessPreCertSubmission(chain, &entry),
                             entry, sct);
}

// static
std::string Frontend::SubmitResultString(SubmitResult result) {
  string result_string;
  switch (result) {
    case ADDED:
      result_string = "new submission accepted";
      break;
    case DUPLICATE:
      result_string = "duplicate submission";
    case BAD_PEM_FORMAT:
      result_string = "not a valid PEM-encoded chain";
      break;
    // TODO(ekasper): the following two could/should be more precise.
    case SUBMISSION_TOO_LONG:
      result_string =
          "DER-encoded certificate chain length "
          "exceeds allowed limit";
      break;
    case CERTIFICATE_VERIFY_ERROR:
      result_string = "could not verify certificate chain";
      break;
    case PRECERT_CHAIN_NOT_WELL_FORMED:
      result_string = "precert chain not well-formed";
      break;
    case INTERNAL_ERROR:
      result_string = "internal error";
      break;
    default:
      LOG(FATAL) << "Unknown SubmissionHandler return code " << result;
  }

  return result_string;
}

// static
SubmitResult Frontend::GetSubmitError(
    CertSubmissionHandler::SubmitResult result) {
  CHECK_NE(result, CertSubmissionHandler::OK);

  SubmitResult submit_result;
  switch (result) {
    case CertSubmissionHandler::EMPTY_SUBMISSION:
    case CertSubmissionHandler::INVALID_PEM_ENCODED_CHAIN:
      submit_result = BAD_PEM_FORMAT;
      break;
    case CertSubmissionHandler::SUBMISSION_TOO_LONG:
      submit_result = SUBMISSION_TOO_LONG;
      break;
    case CertSubmissionHandler::INVALID_CERTIFICATE_CHAIN:
    case CertSubmissionHandler::UNKNOWN_ROOT:
      submit_result = CERTIFICATE_VERIFY_ERROR;
      break;
    case CertSubmissionHandler::PRECERT_CHAIN_NOT_WELL_FORMED:
      submit_result = PRECERT_CHAIN_NOT_WELL_FORMED;
      break;
    case CertSubmissionHandler::INTERNAL_ERROR:
      submit_result = INTERNAL_ERROR;
      break;
    default:
      LOG(FATAL) << "Unknown CertSubmissionHandler return code " << result;
  }
  return submit_result;
}

void Frontend::UpdateStats(ct::LogEntryType type, SubmitResult result) {
  if (type == ct::X509_ENTRY)
    UpdateX509Stats(result);
  else
    UpdatePrecertStats(result);
}

void Frontend::UpdateX509Stats(SubmitResult result) {
  lock_guard<mutex> lock(stats_mutex_);
  switch (result) {
    case ADDED:
      ++stats_.x509_accepted;
      break;
    case DUPLICATE:
      ++stats_.x509_duplicates;
      break;
    case BAD_PEM_FORMAT:
      ++stats_.x509_bad_pem_certs;
      break;
    case SUBMISSION_TOO_LONG:
      ++stats_.x509_too_long_certs;
      break;
    case CERTIFICATE_VERIFY_ERROR:
      ++stats_.x509_verify_errors;
      break;
    case INTERNAL_ERROR:
      ++stats_.internal_errors;
      break;
    case PRECERT_CHAIN_NOT_WELL_FORMED:
      LOG(FATAL) << "invalid PRECERT_CHAIN_NOT_WELL_FORMED on an X509 certificate";
    default:
      LOG(FATAL) << "unknown SubmitResult enum value: " << result;
  }
}

void Frontend::UpdatePrecertStats(SubmitResult result) {
  lock_guard<mutex> lock(stats_mutex_);
  switch (result) {
    case ADDED:
      ++stats_.precert_accepted;
      break;
    case DUPLICATE:
      ++stats_.precert_duplicates;
      break;
    case BAD_PEM_FORMAT:
      ++stats_.precert_bad_pem_certs;
      break;
    case SUBMISSION_TOO_LONG:
      ++stats_.precert_too_long_certs;
      break;
    case CERTIFICATE_VERIFY_ERROR:
      ++stats_.precert_verify_errors;
      break;
    case PRECERT_CHAIN_NOT_WELL_FORMED:
      ++stats_.precert_format_errors;
      break;
    case INTERNAL_ERROR:
      ++stats_.internal_errors;
      break;
    default:
      LOG(FATAL) << "unknown SubmitResult enum value: " << result;
  }
}
