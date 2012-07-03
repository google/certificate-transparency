#include <assert.h>
#include <iostream>
#include <stddef.h>
#include <string>

#include "../include/types.h"
#include "../util/util.h"
#include "SerialHasher.h"

namespace {

const unsigned char kTestString[] = "Hello world!";
const size_t kTestStringLength = 12;

typedef struct {
  size_t input_length;
  const char *input;
  const char *output;
} HashTestVector;

// A couple of SHA-256 test vectors from http://csrc.nist.gov/groups/STM/cavp/
HashTestVector test_sha256[] = {
  { 0,
    "",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
  { 8,
    "5738c929c4f4ccb6",
    "963bb88f27f512777aab6c8b1a02c70ec0ad651d428f870036e1917120fb48bf" },
  { 63,
    "e2f76e97606a872e317439f1a03fcd92e632e5bd4e7cbc4e97f1afc19a16fde9"
    "2d77cbe546416b51640cddb92af996534dfd81edb17c4424cf1ac4d75aceeb",
    "18041bd4665083001fba8c5411d2d748e8abbfdcdfd9218cb02b68a78e7d4c23" },
  // to indicate the end
  { 0, NULL, NULL }
};

// Known Answer Tests
void KatTest(SerialHasher *hasher, HashTestVector test_vector[]) {
  bstring input, output, digest;

  for (int i = 0; test_vector[i].input != NULL; ++i) {
    std::string hex_input(test_vector[i].input, test_vector[i].input_length * 2);
    std::string hex_output(test_vector[i].output, hasher->DigestSize() * 2);
    input = util::BinaryString(hex_input);
    output = util::BinaryString(hex_output);
    hasher->Reset();
    hasher->Update(input);
    digest = hasher->Final();
    assert(digest == output);
  }
}

// Test fragmented updates
void UpdateTest(SerialHasher *hasher) {
  bstring input(kTestString, kTestStringLength),  output, digest;

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
