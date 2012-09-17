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

// Write to a temporary file and return the filename, or an
// empty string on error.
std::string WriteTemporaryBinaryFile(const std::string &file_template,
                                     const bstring &data);

// Create a temporary directory, and return the dirname, or an
// empty string on error.
std::string CreateTemporaryDirectory(const std::string &dir_template);

uint64_t TimeInMilliseconds();

}  // namespace util
#endif
