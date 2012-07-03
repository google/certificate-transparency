#ifndef UTIL_H
#define UTIL_H

#include <string>

#include "../include/types.h"

namespace util {

std::string HexString(const bstring &data);

std::string HexString(const bstring &data, char byte_delimiter);

bstring BinaryString(const std::string &hex_string);

// Serialize MSB to LSB, write |bytes| least significant bytes.
bstring SerializeUint(size_t in, size_t bytes);

size_t DeserializeUint(const bstring &in);

bool ReadTextFile(const std::string &file, std::string *result);

bool ReadBinaryFile(const std::string &file, bstring *result);

}  // namespace util
#endif
