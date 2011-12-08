#ifndef SERIALHASHER_H
#define SERIALHASHER_H
#include <string>

class SerialHasher {
 public:
  SerialHasher() {}
  ~SerialHasher() {}

  virtual size_t DigestSize() = 0;
  virtual void Reset() = 0;
  virtual void Update(const std::string &data) = 0;
  virtual void Final(std::string *digest) = 0;
};

class SHA256Hasher : public SerialHasher {
  // Implement virtuals using OpenSSL.
};
#endif
