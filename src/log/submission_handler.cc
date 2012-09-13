#include "ct.pb.h"
#include "serializer.h"
#include "submission_handler.h"
#include "types.h"

using ct::CertificateEntry;

SubmissionHandler::SubmitResult
SubmissionHandler::ProcessSubmission(const bstring &submission,
                                     CertificateEntry *entry) {
  assert(entry != NULL);
  assert(entry->has_type());

  if (submission.empty())
    return EMPTY_SUBMISSION;

  SubmitResult submit_result = INVALID_TYPE;
  switch(entry->type()) {
    case CertificateEntry::X509_ENTRY:
      submit_result = ProcessX509Submission(submission, entry);
      break;
    case CertificateEntry::PRECERT_ENTRY:
      submit_result = ProcessPreCertSubmission(submission, entry);
      break;
    default:
      // We support all types, so we should currently never get here.
      assert(false);
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

// Default (for testing) - no verification,
// just write the submission in the leaf cert field.
SubmissionHandler::SubmitResult
SubmissionHandler::ProcessX509Submission(const bstring &submission,
                                         CertificateEntry *entry) {
  entry->set_leaf_certificate(submission);
  return OK;
}

// Default (for testing) - no verification,
// just write the submission in the leaf cert field.
SubmissionHandler::SubmitResult
SubmissionHandler::ProcessPreCertSubmission(const bstring &submission,
                                            CertificateEntry *entry) {
  entry->set_leaf_certificate(submission);
  return OK;
}

// static
SubmissionHandler::SubmitResult
SubmissionHandler::GetFormatError(Serializer::SerializeResult result) {
  SubmitResult submit_result = UNKNOWN_ERROR;
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
      assert(false);
  }

  return submit_result;
}

// static
SubmissionHandler::SubmitResult
SubmissionHandler::GetVerifyError(CertChecker::CertVerifyResult result) {
  SubmitResult submit_result = UNKNOWN_ERROR;
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
      assert(false);
  }
  return submit_result;
}
