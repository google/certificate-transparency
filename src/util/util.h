#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <string>

#include "types.h"

namespace util {

std::string HexString(const bstring &data);

std::string HexString(const bstring &data, char byte_delimiter);

bstring BinaryString(const std::string &hex_string);

bool ReadTextFile(const std::string &file, std::string *result);

bool ReadBinaryFile(const std::string &file, bstring *result);

uint64_t TimeInMilliseconds();

std::string CreateTemporaryDirectory(const std::string &dir_template);

}  // namespace util
#endif
