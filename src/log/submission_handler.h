#ifndef SUBMISSION_HANDLER_H
#define SUBMISSION_HANDLER_H

#include "../include/types.h"
#include "log_entry.h"

// The submission handler is responsible for parsing submissions and
// deciding whether they are accepted for logging.
// The submission handler controls the entry types that a log accepts.
// The default submission handler accepts only test entries.
class SubmissionHandler {
 public:
  SubmissionHandler() {}
  virtual ~SubmissionHandler() {}

  // Caller owns the result.
  virtual LogEntry *ProcessSubmission(LogEntry::LogEntryType type,
                                      const bstring &submission) const;
};
#endif
