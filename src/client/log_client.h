#ifndef LOG_CLIENT_H
#define LOG_CLIENT_H

#include <stdint.h>

#include "client.h"
#include "ct.h"
#include "ct.pb.h"

// V0 client that speaks the protobuf format.
class LogClient {
 public:
  LogClient(const std::string &server, uint16_t port);

  ~LogClient();

  static const ct::protocol::Version kProtocolVersion;
  static const ct::protocol::Format kPacketFormat;
  static const ct::Version kCtVersion;

  bool Connect();

  void Disconnect();

  bool UploadSubmission(const std::string &submission, bool pre,
                        ct::SignedCertificateTimestamp *sct);

  // Entry must have the leaf certificate set.
  bool QueryAuditProof(const ct::LogEntry &entry,
                       const ct::SignedCertificateTimestamp &sct,
                       ct::MerkleAuditProof *proof);

  static std::string ErrorString(ct::ServerError::ErrorCode error);

 private:
  bool SendMessage(const ct::ClientMessage &message);
  bool ReadReply(ct::ServerMessage *reply);
  Client client_;
};
#endif
