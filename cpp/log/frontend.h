/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef FRONTEND_H
#define FRONTEND_H

#include <mutex>

#include "base/macros.h"
#include "log/cert_submission_handler.h"
#include "log/submit_result.h"
#include "proto/ct.pb.h"

class FrontendSigner;

namespace util {
class Status;
}  // namespace util

// Frontend for accepting new submissions.
class Frontend {
 public:
  // Takes ownership of the handler and signer.
  Frontend(CertSubmissionHandler* handler, FrontendSigner* signer);
  ~Frontend();

  // Note that these might change the |chain|.
  util::Status QueueX509Entry(cert_trans::CertChain* chain,
                              ct::SignedCertificateTimestamp* sct);
  util::Status QueuePreCertEntry(cert_trans::PreCertChain* chain,
                                 ct::SignedCertificateTimestamp* sct);

  static std::string SubmitResultString(SubmitResult result);

  const std::multimap<std::string, const cert_trans::Cert*>& GetRoots() const {
    return handler_->GetRoots();
  }

 private:
  CertSubmissionHandler* handler_;
  FrontendSigner* signer_;

  util::Status QueueProcessedEntry(
      CertSubmissionHandler::SubmitResult pre_result,
      const ct::LogEntry& entry, ct::SignedCertificateTimestamp* sct);
  static util::Status GetSubmitError(
      CertSubmissionHandler::SubmitResult result);
  util::Status UpdateStats(ct::LogEntryType type, const util::Status& result);
  void UpdateX509Stats(const util::Status& status);
  void UpdatePrecertStats(const util::Status& status);

  DISALLOW_COPY_AND_ASSIGN(Frontend);
};
#endif
