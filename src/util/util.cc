#include <assert.h>
#include <iostream>
#include <fstream>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <sys/time.h>

#include "types.h"
#include "util.h"

namespace util {

namespace {
const char nibble[] = "0123456789abcdef";

byte ByteValue(char high, char low) {
  assert(('0' <= high && high <= '9') || ('a' <= high && high <= 'f'));
  assert(('0' <= high && high <= '9') || ('a' <= high && high <= 'f'));
  byte ret;
  if (high <= '9')
    ret = (high - '0') << 4;
  else
    ret = (high - 'W') << 4; // 'a' - 'W' = 0x61 - 0x57 = 0x0a
  if (low <= '9')
    ret += low - '0';
  else
    ret += low - 'W';
  return ret;
}

}  // namespace

size_t PrefixLength(size_t max_length) {
  size_t prefix_length = 0;

  for ( ; max_length > 0; max_length >>= 8)
    ++prefix_length;

  return prefix_length;
}


std::string HexString(const bstring &data) {
  std::string ret;
  for (unsigned int i = 0; i < data.size(); ++i) {
    ret.push_back(nibble[(data[i] >> 4) & 0xf]);
    ret.push_back(nibble[data[i] & 0xf]);
  }
  return ret;
}

std::string HexString(const bstring &data, char byte_delimiter) {
  std::string ret;
  for (unsigned int i = 0; i < data.size(); ++i) {
    ret.push_back(nibble[(data[i] >> 4) & 0xf]);
    ret.push_back(nibble[data[i] & 0xf]);
    ret.push_back(byte_delimiter);
  }
  return ret;
}

bstring BinaryString(const std::string &hex_string) {
  bstring ret;
  assert(!(hex_string.size() % 2));
  for (size_t i = 0; i < hex_string.size(); i += 2)
    ret.push_back(ByteValue(hex_string[i], hex_string[i+1]));
  return ret;
}

static char *ReadFileStreamToBuffer(std::ifstream &in, int *length) {
  assert(in.good());

  in.seekg(0, std::ios::end);
  int file_length = in.tellg();
  // Rewind.
  in.seekg(0, std::ios::beg);

  // Now write the proof.
  char *buf = new char[file_length];
  in.read(buf, file_length);
  assert(!in.bad());
  assert(in.gcount() == file_length);
  in.close();

  *length = file_length;
  return buf;
}

bool ReadTextFile(const std::string &file, std::string *contents) {
  int file_length;
  std::ifstream in(file.c_str(), std::ios::in);
  if (!in.good())
    return false;
  char *buf = ReadFileStreamToBuffer(in, &file_length);
  contents->assign(std::string(buf, file_length));

  delete[] buf;
  return true;
}

bool ReadBinaryFile(const std::string &file, bstring *contents) {
  int file_length;
  std::ifstream in(file.c_str(), std::ios::in | std::ios::binary);
  if (!in.good())
    return false;

  char *buf = ReadFileStreamToBuffer(in, &file_length);
  contents->assign(bstring(reinterpret_cast<byte*>(buf), file_length));

  delete[] buf;
  return true;
}

uint64_t TimeInMilliseconds() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return static_cast<uint64_t>(tv.tv_sec) * 1000 +
      static_cast<uint64_t>(tv.tv_usec) / 1000;
}

std::string CreateTemporaryDirectory(const std::string &dir_template) {
  size_t strlen = dir_template.size() + 1;
  char *template_buf = new char[strlen];
  memcpy(template_buf, dir_template.data(), dir_template.size());
  template_buf[strlen - 1] = '\0';
  char *tmpdir = mkdtemp(template_buf);
  std::string ret;
  if (tmpdir != NULL)
    ret = std::string(tmpdir);
  delete[] template_buf;
  return ret;
}

} // namespace util
