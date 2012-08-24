#ifndef SERIALHASHER_H
#define SERIALHASHER_H

#include <openssl/sha.h>
#include <stddef.h>

#include "types.h"

class SerialHasher {
 public:
  SerialHasher() {}
  virtual ~SerialHasher() {}

  virtual size_t DigestSize() const = 0;
  virtual void Reset() = 0;
  virtual void Update(const bstring &data) = 0;
  virtual bstring Final() = 0;
};

class Sha256Hasher : public SerialHasher {
 public:
  Sha256Hasher();

  size_t DigestSize() const { return kDigestSize; }

  void Reset();
  void Update(const bstring &data);
  bstring Final();

 private:
  SHA256_CTX ctx_;
  bool initialized_;
  static const size_t kDigestSize;
};
#endif
