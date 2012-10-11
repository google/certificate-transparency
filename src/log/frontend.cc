#include <glog/logging.h>

#include "ct.pb.h"
#include "frontend.h"
#include "frontend_signer.h"
#include "cert_submission_handler.h"

using ct::CertificateEntry;
using ct::SignedCertificateTimestamp;
using std::string;

Frontend::Frontend(CertSubmissionHandler *handler, FrontendSigner *signer)
    : handler_(handler),
      signer_(signer) {}

Frontend::~Frontend() {
  delete signer_;
  delete handler_;
}

Frontend::SubmitResult Frontend::QueueEntry(CertificateEntry::Type type,
                                            const string &data,
                                            SignedCertificateTimestamp *sct) {
  // Step 1. Preprocessing: convert the submission into a CertificateEntry
  // and verify the chain.
  CertificateEntry entry;
  entry.set_type(type);
  CertSubmissionHandler::SubmitResult pre_result =
      handler_->ProcessSubmission(data, &entry);
  if (pre_result != CertSubmissionHandler::OK)
    return GetSubmitError(pre_result);

  // Step 2. Submit to database.
  FrontendSigner::SubmitResult signer_result = signer_->QueueEntry(entry, sct);

  SubmitResult result;
  switch (signer_result) {
    case NEW:
      result = NEW;
      break;
    case DUPLICATE:
      result = DUPLICATE;
      break;
    default:
      LOG(FATAL) << "Unknown FrontendSigner return code " << signer_result;
  }

  return result;
}

// static
std::string Frontend::SubmitResultString(SubmitResult result) {
  string result_string;
  switch (result) {
    case NEW:
      result_string = "new submission accepted";
      break;
    case DUPLICATE:
      result_string = "duplicate submission";
    case BAD_PEM_FORMAT:
      result_string = "not a valid PEM-encoded chain";
      break;
      // TODO(ekasper): the following two could/should be more precise.
    case SUBMISSION_TOO_LONG:
      result_string = "DER-encoded certificate chain length "
          "exceeds allowed limit";
      break;
    case CERTIFICATE_VERIFY_ERROR:
      result_string = "could not verify certificate chain";
      break;
    case PRECERT_CHAIN_NOT_WELL_FORMED:
      result_string = "precert chain not well-formed";
      break;
    default:
      LOG(FATAL) << "Unknown SubmissionHandler return code " << result;
  }

  return result_string;
}

// static
Frontend::SubmitResult
Frontend::GetSubmitError(CertSubmissionHandler::SubmitResult result) {
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
    default:
      LOG(FATAL) << "Unknown CertSubmissionHandler return code " << result;
  }
  return submit_result;
}
