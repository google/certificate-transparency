#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <string>

namespace util {

std::string HexString(const std::string &data);

std::string HexString(const std::string &data, char byte_delimiter);

std::string BinaryString(const std::string &hex_string);

bool ReadTextFile(const std::string &file, std::string *result);

bool ReadBinaryFile(const std::string &file, std::string *result);

// Write to a temporary file and return the filename, or an
// empty string on error.
std::string WriteTemporaryBinaryFile(const std::string &file_template,
                                     const std::string &data);

// Create a temporary directory, and return the dirname, or an
// empty string on error.
std::string CreateTemporaryDirectory(const std::string &dir_template);

uint64_t TimeInMilliseconds();

}  // namespace util
#endif
