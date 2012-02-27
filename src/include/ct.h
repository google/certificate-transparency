#include <string>

typedef unsigned char byte;
typedef std::basic_string<byte> bstring;

// Some codes that we send across the wire.
namespace ct {

// Client commands the server understands.
// One byte.
enum ClientCommand {
  UPLOAD_BUNDLE = 1,
};

// The server's response codes.
// One byte.
enum ServerResponse {
  ERROR = 0,
  SUBMITTED = 1,
  LOGGED = 2,
};

// The server's error codes sent with response code ERROR.
enum ServerError {
  BAD_VERSION = 0,
  BAD_COMMAND = 1,
};

} // namespace ct
