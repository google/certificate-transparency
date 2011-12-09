#include <assert.h>
#include <iostream>
#include <string>

#include "SerialHasher.h"

namespace {

typedef struct {
  size_t input_length;
  const char *input;
  const char *output;
} HashTestVector;

// A couple of SHA-256 test vectors from http://csrc.nist.gov/groups/STM/cavp/
HashTestVector test_sha256[] = {
  { 0,
    "",
    "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
    "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55" },
  { 8,
    "\x57\x38\xc9\x29\xc4\xf4\xcc\xb6",
    "\x96\x3b\xb8\x8f\x27\xf5\x12\x77\x7a\xab\x6c\x8b\x1a\x02\xc7\x0e"
    "\xc0\xad\x65\x1d\x42\x8f\x87\x00\x36\xe1\x91\x71\x20\xfb\x48\xbf" },
  { 63,
    "\xe2\xf7\x6e\x97\x60\x6a\x87\x2e\x31\x74\x39\xf1\xa0\x3f\xcd\x92"
    "\xe6\x32\xe5\xbd\x4e\x7c\xbc\x4e\x97\xf1\xaf\xc1\x9a\x16\xfd\xe9"
    "\x2d\x77\xcb\xe5\x46\x41\x6b\x51\x64\x0c\xdd\xb9\x2a\xf9\x96\x53"
    "\x4d\xfd\x81\xed\xb1\x7c\x44\x24\xcf\x1a\xc4\xd7\x5a\xce\xeb",
    "\x18\x04\x1b\xd4\x66\x50\x83\x00\x1f\xba\x8c\x54\x11\xd2\xd7\x48"
    "\xe8\xab\xbf\xdc\xdf\xd9\x21\x8c\xb0\x2b\x68\xa7\x8e\x7d\x4c\x23" },
  // to indicate the end
  { 0, NULL, NULL }
};

// Known Answer Tests
void KatTest(SerialHasher *hasher, HashTestVector test_vector[]) {
  std::string input, output, digest;

  for (int i = 0; test_vector[i].input != NULL; ++i) {
    input.assign(test_vector[i].input, test_vector[i].input_length);
    output.assign(test_vector[i].output, hasher->DigestSize());
    hasher->Reset();
    hasher->Update(input);
    digest = hasher->Final();
    assert(digest == output);
  }
}

// Test fragmented updates
void UpdateTest(SerialHasher *hasher) {
  std::string input = "Hello world!", output, digest;

  hasher->Reset();
  hasher->Update(input);
  digest = hasher->Final();
  assert(digest.size() == hasher->DigestSize());

  // The same in two chunks
  hasher->Reset();
  hasher->Update(input.substr(0,5));
  hasher->Update(input.substr(5));
  output = hasher->Final();
  assert(digest == output);
}


void Sha256Test() {
  Sha256Hasher hasher;
  KatTest(&hasher, test_sha256);
  UpdateTest(&hasher);
}

} // namespace

int main(int, char**) {
  std::cout << "SHA-256... ";
  Sha256Test();
  std::cout << "PASS\n";
  return 0;
}
