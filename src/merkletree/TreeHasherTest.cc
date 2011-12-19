#include <assert.h>
#include <iostream>
#include <stddef.h>
#include <string>

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
    "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
    "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55";

LeafTestVector sha256_leaves[] = {
  { 0,
    "",
    "\x6e\x34\x0b\x9c\xff\xb3\x7a\x98\x9c\xa5\x44\xe6\xbb\x78\x0a\x2c"
    "\x78\x90\x1d\x3f\xb3\x37\x38\x76\x85\x11\xa3\x06\x17\xaf\xa0\x1d" },
  { 1,
    "\x00",
    "\x96\xa2\x96\xd2\x24\xf2\x85\xc6\x7b\xee\x93\xc3\x0f\x8a\x30\x91"
    "\x57\xf0\xda\xa3\x5d\xc5\xb8\x7e\x41\x0b\x78\x63\x0a\x09\xcf\xc7" },

  { 16,
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
    "\x3b\xfb\x96\x04\x53\xeb\xae\xbf\x33\x72\x7d\xa7\xa1\xf4\xdb\x38"
    "\xac\xc0\x51\xd3\x81\xb6\xda\x20\xd6\xd4\xe8\x8f\x0e\xab\xfd\x7a" },
  { 0, NULL, NULL}
};

NodeTestVector sha256_nodes[] = {
  { "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
    "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f",
    "\x1a\x37\x87\x04\xc1\x7d\xa3\x1e\x2d\x05\xb6\xd1\x21\xc2\xbb\x2c"
    "\x7d\x76\xf6\xee\x6f\xa8\xf9\x83\xe5\x96\xc2\xd0\x34\x96\x3c\x57" },
  { NULL, NULL, NULL }
};

// TreeHashers are collision resistant when used correctly, i.e.,
// when HashChildren() is called on the (fixed-length) outputs of HashLeaf().
void CollisionTest(TreeHasher *treehasher) {
  std::string leaf1_digest, leaf2_digest, node1_digest, node2_digest;

  const size_t digestsize = treehasher->DigestSize();

  // Check that the empty hash is not the same as the hash of an empty leaf.
  leaf1_digest = treehasher->HashEmpty();
  assert(leaf1_digest.size() == digestsize);

  leaf2_digest = treehasher->HashLeaf("");
  assert(leaf2_digest.size() == digestsize);

  assert(leaf1_digest != leaf2_digest);

  // Check that different leaves hash to different digests.
  std::string leaf1 = "Hello";
  std::string leaf2 = "World";
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

void KatTest(TreeHasher *treehasher, const char *empty_hash,
             LeafTestVector leaves[], NodeTestVector nodes[]) {
  const size_t digestsize = treehasher->DigestSize();
  std::string leaf, left, right, output, digest;

  // The empty hash
  output.assign(empty_hash, digestsize);
  digest = treehasher->HashEmpty();
  assert(output == digest);

  // Leaf hashes
  for (int i = 0; leaves[i].input != NULL; ++i) {
    leaf.assign(leaves[i].input, leaves[i].input_length);
    output.assign(leaves[i].output,digestsize);
    digest = treehasher->HashLeaf(leaf);
    assert(output == digest);
  }

  // Node hashes
  for (int i = 0; nodes[i].left != NULL; ++i) {
    left.assign(nodes[i].left, digestsize);
    right.assign(nodes[i].right, digestsize);
    output.assign(nodes[i].output, digestsize);
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
