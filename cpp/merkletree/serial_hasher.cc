#include "merkletree/serial_hasher.h"

#include <openssl/sha.h>
#include <stddef.h>

using std::string;
using std::unique_ptr;

const size_t Sha256Hasher::kDigestSize = SHA256_DIGEST_LENGTH;

Sha256Hasher::Sha256Hasher() : initialized_(false) {
}

void Sha256Hasher::Reset() {
  SHA256_Init(&ctx_);
  initialized_ = true;
}

void Sha256Hasher::Update(const std::string& data) {
  if (!initialized_)
    Reset();

  SHA256_Update(&ctx_, data.data(), data.size());
}

string Sha256Hasher::Final() {
  if (!initialized_)
    Reset();

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_Final(hash, &ctx_);
  initialized_ = false;
  return string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

unique_ptr<SerialHasher> Sha256Hasher::Create() const {
  return unique_ptr<SerialHasher>(new Sha256Hasher);
}

// static
string Sha256Hasher::Sha256Digest(const string& data) {
  Sha256Hasher hasher;
  hasher.Reset();
  hasher.Update(data);
  return hasher.Final();
}
