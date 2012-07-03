#include <assert.h>
#include <iostream>
#include <fstream>
#include <string>

#include "../include/types.h"
#include "util.h"



namespace util {

static const char nibble[] = "0123456789abcdef";

static const byte ByteValue(char high, char low) {
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

bstring SerializeUint(size_t in, size_t bytes) {
  assert(bytes <= sizeof in);
  assert(bytes == sizeof in || in >> (bytes * 8) == 0);
  bstring result;
  for ( ; bytes > 0; --bytes)
    result.push_back((char)
                     ((in & (0xff << ((bytes - 1) * 8))) >> ((bytes - 1) * 8)));
  return result;
}

size_t DeserializeUint(const bstring &in) {
  size_t len = in.length();
  assert(len <= sizeof(size_t));
  size_t res = 0;
  for (size_t i = 0; i < len; ++i)
    res = (res << 8) + in[i];
  return res;
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
  contents->assign(bstring(reinterpret_cast<unsigned char*>(buf), file_length));

  delete[] buf;
  return true;
}

} // namespace util
