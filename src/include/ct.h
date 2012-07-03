#ifndef CT_H
#define CT_H

#include "types.h"

// Some codes that we send across the wire.
namespace ct {

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
  SUBMITTED = 1,
  LOGGED = 2,
};

// The server's error codes sent with response code ERROR.
// One byte.
enum ServerError {
  BAD_VERSION = 0,
  BAD_COMMAND = 1,
  BAD_BUNDLE = 2,
};

} // namespace ct
#endif
