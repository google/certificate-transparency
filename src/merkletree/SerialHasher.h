#ifndef SERIALHASHER_H
#define SERIALHASHER_H
#include <openssl/sha.h>
#include <string>

class SerialHasher {
 public:
  SerialHasher() {}
  ~SerialHasher() {}

  virtual size_t DigestSize() const = 0;
  virtual void Reset() = 0;
  virtual void Update(const std::string &data) = 0;
  virtual void Final(std::string *digest) = 0;
};

class Sha256Hasher : public SerialHasher {
 public:
  static const size_t kDigestSize;

  Sha256Hasher();
  ~Sha256Hasher();

  size_t DigestSize() const {
    return kDigestSize;
  }

  void Reset();
  void Update(const std::string &data);
  void Final(std::string *digest);

 private:
  SHA256_CTX ctx_;
  bool initialized_;
};
#endif
