#include "../include/types.h"
#include "log_entry.h"
#include "submission_handler.h"

// No real processing.
LogEntry
*SubmissionHandler::ProcessSubmission(LogEntry::LogEntryType type,
                                      const bstring &submission) const {
  if (submission.empty())
    return NULL;

  LogEntry *entry = NULL;
  switch(type) {
    case LogEntry::TEST_ENTRY:
      entry = new TestEntry(submission);
      break;
    default:
      // Don't know how to handle those.
      break;
  }

  return entry;
}
