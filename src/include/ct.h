#ifndef CT_H
#define CT_H

#include "types.h"

// Some codes that we send across the wire.
namespace ct {

// Packet format:
// Command/response - 1 byte
// Length - 3 bytes
// Data - < |length| bytes

// Client commands the server understands.
// One byte.
enum ClientCommand {
  // Upload a certificate bundle, and retrieve
  // a submission token, or an audit proof.
  UPLOAD_BUNDLE = 1,
  UPLOAD_CA_BUNDLE = 2,
};

// The server's response codes.
// One byte.
enum ServerResponse {
  ERROR = 0,
  SIGNED_CERTIFICATE_TIMESTAMP = 1,
  LOGGED = 2,
};

// Error message format:
// Error code - 1 byte.
// (Optional) human-readable error.

// The server's error codes sent with response code ERROR.
// One byte.
enum ServerError {
  BAD_VERSION = 0,
  BAD_COMMAND = 1,
  REJECTED = 2,
};

} // namespace ct
#endif
