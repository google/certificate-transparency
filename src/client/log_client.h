#ifndef LOG_CLIENT_H
#define LOG_CLIENT_H

#include <stdint.h>

#include "client.h"
#include "ct.h"
#include "ct.pb.h"
#include "types.h"

// V0 client that speaks the protobuf format.
class LogClient {
 public:
  LogClient(const std::string &server, uint16_t port);

  ~LogClient();

  static const ct::Version kVersion;
  static const ct::MessageFormat kFormat;
  static const size_t kPacketPrefixLength;
  static const size_t kMaxPacketLength;

  bool Connect();

  void Disconnect();

  bool UploadSubmission(const bstring &submission, bool pre,
                        ct::SignedCertificateTimestamp *sct);

  static std::string ErrorString(ct::ServerError::ErrorCode error);

 private:
  bool SendMessage(const ct::ClientMessage &message);
  bool ReadReply(ct::ServerMessage *reply);
  Client client_;
};
#endif
