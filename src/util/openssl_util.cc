#include "util/openssl_util.h"

#include <openssl/err.h>

#include <string>

namespace util {

using std::string;

string DumpOpenSSLErrorStack() {
  if (ERR_peek_error() == 0)
    return "No OpenSSL errors left on stack";

  string stack_dump("OpenSSL errors left on stack:");
  unsigned long error;
  char error_string[256];
  while ((error = ERR_get_error()) != 0) {
    stack_dump.append("\n\t");
    ERR_error_string_n(error, error_string, 256);
    stack_dump.append(error_string);
  }
  return stack_dump;
}

void ClearOpenSSLErrors() {
  ERR_clear_error();
}


}  // namespace util
