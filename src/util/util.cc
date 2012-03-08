#include "../include/ct.h"
#include "util.h"

#include <string>

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

} // namespace util
