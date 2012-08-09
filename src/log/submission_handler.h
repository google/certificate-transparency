#ifndef SUBMISSION_HANDLER_H
#define SUBMISSION_HANDLER_H

#include "../include/types.h"
#include "../proto/ct.pb.h"

// The submission handler is responsible for parsing submissions and
// deciding whether they are accepted for logging.
class SubmissionHandler {
 public:
  SubmissionHandler() {}
  virtual ~SubmissionHandler() {}

  // Caller owns the result.
  CertificateEntry *ProcessSubmission(CertificateEntry::Type type,
                                      const bstring &submission);

 protected:
  virtual bool ProcessX509Submission(const bstring &submission,
                                     CertificateEntry *entry);
  virtual bool ProcessPreCertSubmission(const bstring &submission,
                                    CertificateEntry *entry);
};
#endif
