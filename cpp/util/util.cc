#include "util/util.h"

#include <modp_b64.h>
#include <cstring>
#include <fstream>
#include <glog/logging.h>
#include <iostream>
#include <netinet/in.h>  // for resolv.h
#include <resolv.h>      // for b64_ntop
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/time.h>
#include <unistd.h>

using std::string;

namespace util {

namespace {
const char nibble[] = "0123456789abcdef";

char ByteValue(char high, char low) {
  CHECK(('0' <= high && high <= '9') || ('a' <= high && high <= 'f'));
  char ret;
  if (high <= '9')
    ret = (high - '0') << 4;
  else
    ret = (high - 'W') << 4;  // 'a' - 'W' = 0x61 - 0x57 = 0x0a
  if (low <= '9')
    ret += low - '0';
  else
    ret += low - 'W';
  return ret;
}

}  // namespace

string HexString(const string& data) {
  string ret;
  for (unsigned int i = 0; i < data.size(); ++i) {
    ret.push_back(nibble[(data[i] >> 4) & 0xf]);
    ret.push_back(nibble[data[i] & 0xf]);
  }
  return ret;
}

string HexString(const string& data, char byte_delimiter) {
  string ret;
  if (data.empty())
    return ret;
  for (unsigned int i = 0; i < data.size(); ++i) {
    if (i != 0)
      ret.push_back(byte_delimiter);
    ret.push_back(nibble[(data[i] >> 4) & 0xf]);
    ret.push_back(nibble[data[i] & 0xf]);
  }
  return ret;
}

string BinaryString(const string& hex_string) {
  string ret;
  CHECK(!(hex_string.size() % 2));
  for (size_t i = 0; i < hex_string.size(); i += 2)
    ret.push_back(ByteValue(hex_string[i], hex_string[i + 1]));
  return ret;
}

static char* ReadFileStreamToBuffer(std::ifstream& in, int* length) {
  CHECK(in.good());

  in.seekg(0, std::ios::end);
  int file_length = in.tellg();
  // Rewind.
  in.seekg(0, std::ios::beg);

  // Now write the proof.
  char* buf = new char[file_length];
  in.read(buf, file_length);
  CHECK(!in.bad());
  CHECK_EQ(in.gcount(), file_length);
  in.close();

  *length = file_length;
  return buf;
}

bool ReadTextFile(const string& file, string* contents) {
  int file_length;
  std::ifstream in(file.c_str(), std::ios::in);
  if (!in.good())
    return false;
  char* buf = ReadFileStreamToBuffer(in, &file_length);
  contents->assign(string(buf, file_length));

  delete[] buf;
  return true;
}

bool ReadBinaryFile(const string& file, string* contents) {
  int file_length;
  std::ifstream in(file.c_str(), std::ios::in | std::ios::binary);
  if (!in.good())
    return false;

  char* buf = ReadFileStreamToBuffer(in, &file_length);
  contents->assign(string(buf, file_length));

  delete[] buf;
  return true;
}

string WriteTemporaryBinaryFile(const string& file_template,
                                const string& data) {
  size_t strlen = file_template.size() + 1;
  char* template_buf = new char[strlen];
  memcpy(template_buf, file_template.data(), file_template.size());
  template_buf[strlen - 1] = '\0';
  int fd = mkstemp(template_buf);
  string tmp_file;
  if (fd >= 0) {
    tmp_file = string(template_buf);
    ssize_t bytes_written =
        write(fd, reinterpret_cast<const char*>(data.data()), data.length());
    close(fd);
    if (bytes_written < 0 ||
        static_cast<size_t>(bytes_written) < data.length()) {
      // Write failed; try to clean up.
      remove(tmp_file.c_str());
      tmp_file.clear();
    }
  }
  delete[] template_buf;
  return tmp_file;
}

string CreateTemporaryDirectory(const string& dir_template) {
  size_t strlen = dir_template.size() + 1;
  char* template_buf = new char[strlen];
  memcpy(template_buf, dir_template.data(), dir_template.size());
  template_buf[strlen - 1] = '\0';
  char* tmpdir = mkdtemp(template_buf);
  string ret;
  if (tmpdir != NULL)
    ret = string(tmpdir);
  delete[] template_buf;
  return ret;
}

uint64_t TimeInMilliseconds() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return static_cast<uint64_t>(tv.tv_sec) * 1000 +
         static_cast<uint64_t>(tv.tv_usec) / 1000;
}

string RandomString(size_t min_length, size_t max_length) {
  size_t length = min_length == max_length
                      ? min_length
                      : rand() % (max_length - min_length) + min_length;

  string ret;
  for (; length > 0; --length)
    ret.append(1, rand() & 0xff);

  return ret;
}

string FromBase64(const string& b64) {
  return FromBase64(b64.data(), b64.length());
}

string FromBase64(const char* b64) {
  size_t length = strlen(b64);
  return FromBase64(b64, length);
}

string FromBase64(const char* b64, size_t length) {
  // Lazy: base 64 encoding is always >= in length to decoded value
  // (equality occurs for zero length).
  char* buf = new char[modp_b64_decode_len(length)];
  int rlength = modp_b64_decode(buf, b64, length);
  // Treat decode errors as empty strings.
  if (rlength < 0)
    rlength = 0;
  string ret(buf, rlength);
  delete[] buf;
  return ret;
}

string ToBase64(const string& from) {
  // base 64 is 4 output bytes for every 3 input bytes (rounded up).
  size_t length = modp_b64_encode_len(from.length());
  char* buf = new char[length + 1];
  length = modp_b64_encode(buf, from.data(), from.length());
  string ret(buf, length);
  delete[] buf;
  return ret;
}

}  // namespace util
