/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef FRONTEND_H
#define FRONTEND_H

#include <memory>
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

  const std::multimap<std::string, const cert_trans::Cert*>& GetRoots() const {
    return handler_->GetRoots();
  }

 private:
  const std::unique_ptr<CertSubmissionHandler> handler_;
  const std::unique_ptr<FrontendSigner> signer_;

  util::Status QueueProcessedEntry(util::Status pre_status,
                                   const ct::LogEntry& entry,
                                   ct::SignedCertificateTimestamp* sct);

  DISALLOW_COPY_AND_ASSIGN(Frontend);
};
#endif
