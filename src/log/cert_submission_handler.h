#ifndef CERT_SUBMISSION_HANDLER_H
#define CERT_SUBMISSION_HANDLER_H

#include "../include/types.h"
#include "cert_checker.h"
#include "log_entry.h"
#include "submission_handler.h"


// Parse incoming submissions, do preliminary sanity checks and pass them
// through cert checker.
// Prepare for signing by parsing the input into an appropriate
// log entry structure.
class CertSubmissionHandler : public SubmissionHandler {
 public:
  // Does not take ownership of the cert_checker.
  CertSubmissionHandler(CertChecker *cert_checker);
  ~CertSubmissionHandler() {}

  // Caller owns the result.
  LogEntry *ProcessSubmission(LogEntry::LogEntryType type,
                              const bstring &submission) const;
 private:
  X509ChainEntry *ProcessX509Submission(const bstring &submission) const;

  ProtoCertChainEntry *ProcessProtoSubmission(const bstring &submission) const;

  CertChecker *cert_checker_;
};
#endif
