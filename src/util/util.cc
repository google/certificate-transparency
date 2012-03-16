#include "../include/ct.h"
#include "util.h"

#include <string>

#include <assert.h>

namespace util {

static const char nibble[] = "0123456789abcdef";

std::string HexString(const bstring &data) {
  std::string ret;
  for (unsigned int i = 0; i < data.size(); ++i) {
    ret.push_back(nibble[(data[i] >> 4) & 0xf]);
    ret.push_back(nibble[data[i] & 0xf]);
    ret.push_back(' ');
  }
  return ret;
}

std::string SerializeUint(size_t in, size_t bytes) {
  assert(bytes <= sizeof in);
  assert(bytes == sizeof in || in >> (bytes * 8) == 0);
  std::string result;
  for ( ; bytes > 0; --bytes)
    result.push_back((char)
                     ((in & (0xff << ((bytes - 1) * 8))) >> ((bytes - 1) * 8)));
  return result;
}

size_t DeserializeUint(const std::string &in) {
  size_t len = in.length();
  assert(len <= sizeof(size_t));
  size_t res = 0;
  for (size_t i = 0; i < len; ++i)
    res = (res << 8) + in[i];
  return res;
}


} // namespace util
