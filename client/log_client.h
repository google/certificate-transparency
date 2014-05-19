#ifndef LOG_CLIENT_H
#define LOG_CLIENT_H

#include <stdint.h>

#include "include/ct.h"
#include "client/client.h"
#include "proto/ct.pb.h"

// V1 client that speaks the protobuf format.
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

  bool QueryAuditProof(const std::string &merkle_leaf_hash,
                       ct::MerkleAuditProof *proof);

  static std::string ErrorString(ct::ServerError::ErrorCode error);

 private:
  bool SendMessage(const ct::ClientMessage &message);
  bool ReadReply(ct::ServerMessage *reply);
  Client client_;
};
#endif
