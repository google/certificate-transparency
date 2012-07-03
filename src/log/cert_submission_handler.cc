#include <assert.h>
#include <string>

#include "../include/types.h"
#include "cert.h"
#include "cert_checker.h"
#include "cert_submission_handler.h"
#include "log_entry.h"

CertSubmissionHandler::CertSubmissionHandler(CertChecker *cert_checker)
    : cert_checker_(cert_checker) {
  assert(cert_checker_ != NULL);
}

LogEntry
*CertSubmissionHandler::ProcessSubmission(LogEntry::LogEntryType type,
                                          const bstring &submission) const {
  switch(type) {
    case LogEntry::X509_CHAIN_ENTRY:
      return ProcessX509Submission(submission);
    case LogEntry::PROTOCERT_CHAIN_ENTRY:
      return ProcessProtoSubmission(submission);
    default:
      return NULL;
  }
}

// Inputs must be concatenated PEM entries.
X509ChainEntry*
CertSubmissionHandler::ProcessX509Submission(const bstring &submission) const {
  std::string pem_string(reinterpret_cast<const char*>(submission.data()),
                         submission.size());
  CertChain chain(pem_string);
  if (!chain.IsLoaded() || !cert_checker_->CheckCertChain(chain))
    return NULL;

  // We have a valid chain; make the entry.
  // TODO: should we somehow check that it's not, in fact, a protocert chain?
  return new X509ChainEntry(chain);
}

ProtoCertChainEntry*
CertSubmissionHandler::ProcessProtoSubmission(const bstring &submission) const {
  std::string pem_string(reinterpret_cast<const char*>(submission.data()),
                         submission.size());
  ProtoCertChain chain(pem_string);
  if (!chain.IsLoaded() || !cert_checker_->CheckProtoCertChain(chain))
    return NULL;

  // All checks passed; write the entry.
  return new ProtoCertChainEntry(chain);
}
