#ifndef UTIL_H
#define UTIL_H
#include "../include/ct.h"

#include <string>

namespace util {

std::string HexString(const bstring &data);

// Serialize MSB to LSB, write |bytes| least significant bytes.
std::string SerializeUint(size_t in, size_t bytes);

size_t DeserializeUint(const std::string &in);

} // namespace util

#endif
