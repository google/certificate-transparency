#ifndef CERT_TRANS_LOG_FRONTEND_H_
#define CERT_TRANS_LOG_FRONTEND_H_

#include <memory>
#include <mutex>

#include "log/cert.h"
#include "proto/ct.pb.h"

class FrontendSigner;

namespace util {
class Status;
}  // namespace util

// Frontend for accepting new submissions.
class Frontend {
 public:
  // Takes ownership of the signer.
  Frontend(FrontendSigner* signer);
  ~Frontend();
  Frontend(const Frontend&) = delete;
  Frontend& operator=(const Frontend&) = delete;

  util::Status QueueProcessedEntry(util::Status pre_status,
                                   const ct::LogEntry& entry,
                                   ct::SignedCertificateTimestamp* sct);

 private:
  const std::unique_ptr<FrontendSigner> signer_;
};

#endif  // CERT_TRANS_LOG_FRONTEND_H_
