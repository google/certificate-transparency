#include <assert.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/time.h>
#include <unistd.h>

#include "util.h"

namespace util {

using std::string;

namespace {
const char nibble[] = "0123456789abcdef";

char ByteValue(char high, char low) {
  assert(('0' <= high && high <= '9') || ('a' <= high && high <= 'f'));
  assert(('0' <= high && high <= '9') || ('a' <= high && high <= 'f'));
  char ret;
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

string HexString(const string &data) {
  string ret;
  for (unsigned int i = 0; i < data.size(); ++i) {
    ret.push_back(nibble[(data[i] >> 4) & 0xf]);
    ret.push_back(nibble[data[i] & 0xf]);
  }
  return ret;
}

string HexString(const string &data, char byte_delimiter) {
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

string BinaryString(const string &hex_string) {
  string ret;
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

bool ReadTextFile(const string &file, string *contents) {
  int file_length;
  std::ifstream in(file.c_str(), std::ios::in);
  if (!in.good())
    return false;
  char *buf = ReadFileStreamToBuffer(in, &file_length);
  contents->assign(string(buf, file_length));

  delete[] buf;
  return true;
}

bool ReadBinaryFile(const string &file, string *contents) {
  int file_length;
  std::ifstream in(file.c_str(), std::ios::in | std::ios::binary);
  if (!in.good())
    return false;

  char *buf = ReadFileStreamToBuffer(in, &file_length);
  contents->assign(string(buf, file_length));

  delete[] buf;
  return true;
}

string WriteTemporaryBinaryFile(const string &file_template,
                                const string &data) {
  size_t strlen = file_template.size() + 1;
  char *template_buf = new char[strlen];
  memcpy(template_buf, file_template.data(), file_template.size());
  template_buf[strlen - 1] = '\0';
  int fd = mkstemp(template_buf);
  string tmp_file;
  if (fd >= 0) {
    tmp_file = string(template_buf);
    ssize_t bytes_written = write(fd,
                                  reinterpret_cast<const char*>(data.data()),
                                  data.length());
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

string CreateTemporaryDirectory(const string &dir_template) {
  size_t strlen = dir_template.size() + 1;
  char *template_buf = new char[strlen];
  memcpy(template_buf, dir_template.data(), dir_template.size());
  template_buf[strlen - 1] = '\0';
  char *tmpdir = mkdtemp(template_buf);
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

} // namespace util
