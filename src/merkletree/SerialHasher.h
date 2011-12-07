#ifndef HASHER_H
#define HASHER_H
#include <string>

using std::string;

class SerialHasher {
 public:
  SerialHasher() {}
  ~SerialHasher() {}

  virtual size_t DigestSize() = 0;
  virtual void Reset() = 0;
  virtual void Update(const string &data) = 0;
  virtual void Final(string *digest) = 0;
};

class SHA256Hasher : public SerialHasher {
  // Implement virtuals using OpenSSL.
};
#endif
