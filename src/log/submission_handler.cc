#include "../include/types.h"
#include "../proto/serializer.h"
#include "submission_handler.h"

CertificateEntry
*SubmissionHandler::ProcessSubmission(CertificateEntry::Type type,
                                      const bstring &submission) {
  CertificateEntry *entry = new CertificateEntry();
  entry->set_type(type);

  bool is_valid = false;
  switch(entry->type()) {
    case CertificateEntry::X509_ENTRY:
      is_valid = ProcessX509Submission(submission, entry);
      break;
    case CertificateEntry::PRECERT_ENTRY:
      is_valid = ProcessPreCertSubmission(submission, entry);
      break;
    default:
      assert(false);
      break;
  }

  if (!is_valid || !Serializer::CheckFormat(*entry)) {
    delete entry;
    return NULL;
  }

  return entry;
}

// Default (for testing) - no verification,
// just write the submission in the leaf cert field.
bool SubmissionHandler::ProcessX509Submission(const bstring &submission,
                                              CertificateEntry *entry) {
  entry->set_leaf_certificate(submission);
  return entry;
}

// Default (for testing) - no verification,
// just write the submission in the leaf cert field.
bool SubmissionHandler::ProcessPreCertSubmission(const bstring &submission,
                                                 CertificateEntry *entry) {
  entry->set_leaf_certificate(submission);
  return entry;
}
