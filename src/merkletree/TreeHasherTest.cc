#include <assert.h>
#include <iostream>
#include <stddef.h>
#include <string>

#include "../util/util.h"
#include "SerialHasher.h"
#include "TreeHasher.h"

namespace {

typedef struct {
  size_t input_length;
  const char *input;
  const char *output;
} LeafTestVector;

// Inputs and outputs are of fixed digest size.
typedef struct {
  const char *left;
  const char *right;
  const char *output;
} NodeTestVector;

const char sha256_empty_hash[] =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

LeafTestVector sha256_leaves[] = {
  { 0,
    "",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" },
  { 1,
    "00",
    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7" },

  { 16,
    "101112131415161718191a1b1c1d1e1f",
    "3bfb960453ebaebf33727da7a1f4db38acc051d381b6da20d6d4e88f0eabfd7a" },
  { 0, NULL, NULL}
};

NodeTestVector sha256_nodes[] = {
  { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "1a378704c17da31e2d05b6d121c2bb2c7d76f6ee6fa8f983e596c2d034963c57" },
  { NULL, NULL, NULL }
};

// TreeHashers are collision resistant when used correctly, i.e.,
// when HashChildren() is called on the (fixed-length) outputs of HashLeaf().
void CollisionTest(TreeHasher *treehasher) {
  bstring leaf1_digest, leaf2_digest, node1_digest, node2_digest;

  const size_t digestsize = treehasher->DigestSize();

  // Check that the empty hash is not the same as the hash of an empty leaf.
  leaf1_digest = treehasher->HashEmpty();
  assert(leaf1_digest.size() == digestsize);

  leaf2_digest = treehasher->HashLeaf(bstring());
  assert(leaf2_digest.size() == digestsize);

  assert(leaf1_digest != leaf2_digest);

  // Check that different leaves hash to different digests.
  const unsigned char hello[] = "Hello";
  const unsigned char world[] = "World";
  bstring leaf1(hello, 5);
  bstring leaf2(world, 5);
  leaf1_digest = treehasher->HashLeaf(leaf1);
  assert(leaf1_digest.size() == digestsize);

  leaf2_digest = treehasher->HashLeaf(leaf2);
  assert(leaf2_digest.size() == digestsize);

  assert(leaf1_digest != leaf2_digest);

  // Compute an intermediate node digest.
  node1_digest = treehasher->HashChildren(leaf1_digest, leaf2_digest);
  assert(node1_digest.size() == digestsize);

  // Check that this is not the same as a leaf hash of their concatenation.
  node2_digest = treehasher->HashLeaf(leaf1_digest + leaf2_digest);
  assert(node2_digest.size() == digestsize);

  assert(node1_digest != node2_digest);

  // Swap the order of nodes and check that the hash is different.
  node2_digest = treehasher->HashChildren(leaf2_digest, leaf1_digest);
  assert(node2_digest.size() == digestsize);

  assert(node1_digest != node2_digest);
}

void KatTest(TreeHasher *treehasher, const char *hex_empty_hash,
             LeafTestVector leaves[], NodeTestVector nodes[]) {
  const size_t hex_digest_size = treehasher->DigestSize() * 2;
  bstring leaf, left, right, output, digest;

  // The empty hash
  output = util::BinaryString(std::string(hex_empty_hash, hex_digest_size));
  digest = treehasher->HashEmpty();
  assert(output == digest);

  // Leaf hashes
  for (int i = 0; leaves[i].input != NULL; ++i) {
    leaf = util::BinaryString(std::string(leaves[i].input,
                                          leaves[i].input_length * 2));
    output = util::BinaryString(std::string(leaves[i].output, hex_digest_size));
    digest = treehasher->HashLeaf(leaf);
    assert(output == digest);
  }

  // Node hashes
  for (int i = 0; nodes[i].left != NULL; ++i) {
    left = util::BinaryString(std::string(nodes[i].left, hex_digest_size));
    right = util::BinaryString(std::string(nodes[i].right, hex_digest_size));
    output = util::BinaryString(std::string(nodes[i].output, hex_digest_size));
    digest = treehasher->HashChildren(left, right);
    assert(output == digest);
  }
}

void TreeHasherTest() {
  std::cout << "SHA256... ";
  TreeHasher treehasher(new Sha256Hasher());
  CollisionTest(&treehasher);
  KatTest(&treehasher, sha256_empty_hash, sha256_leaves, sha256_nodes);
  std::cout << "OK\n";
}

} // namespace

int main(int, char**) {
  std::cout << "Testing TreeHashers\n";
  TreeHasherTest();
  std::cout << "PASS\n";
  return 0;
}
