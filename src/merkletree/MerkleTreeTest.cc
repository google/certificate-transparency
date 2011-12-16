#include <assert.h>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <time.h>
#include <vector>

#include "MerkleTree.h"
#include "SerialHasher.h"
#include "TreeHasher.h"

namespace {

// A slightly shorter notation for constructing binary blobs.
#define S(str, size) std::string((str), (size))

std::string sha256_empty_tree_hash(
    "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
    "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55", 32);

std::string inputs[8] = {
  "",
  S("\x00", 1),
  S("\x10", 1),
  S("\x20\x21", 2),
  S("\x30\x31", 2),
  S("\x40\x41\x42\x43", 4),
  S("\x50\x51\x52\x53\x54\x55\x56\x57", 8),
  S("\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f", 16),
};

// Level counts for number of leaves in [0, 8]
unsigned int level_counts[8] = {1, 2, 3, 3, 4, 4, 4, 4};

// Incremental roots from building the tree from inputs leaf-by-leaf.
// Generated from ReferenceMerkleTreeHash.
std::string sha256_roots[8] = {
  S("\x6e\x34\x0b\x9c\xff\xb3\x7a\x98\x9c\xa5\x44\xe6\xbb\x78\x0a\x2c"
    "\x78\x90\x1d\x3f\xb3\x37\x38\x76\x85\x11\xa3\x06\x17\xaf\xa0\x1d", 32),
  S("\xfa\xc5\x42\x03\xe7\xcc\x69\x6c\xf0\xdf\xcb\x42\xc9\x2a\x1d\x9d"
    "\xba\xf7\x0a\xd9\xe6\x21\xf4\xbd\x8d\x98\x66\x2f\x00\xe3\xc1\x25", 32),
  S("\xae\xb6\xbc\xfe\x27\x4b\x70\xa1\x4f\xb0\x67\xa5\xe5\x57\x82\x64"
    "\xdb\x0f\xa9\xb5\x1a\xf5\xe0\xba\x15\x91\x58\xf3\x29\xe0\x6e\x77", 32),
  S("\xd3\x7e\xe4\x18\x97\x6d\xd9\x57\x53\xc1\xc7\x38\x62\xb9\x39\x8f"
    "\xa2\xa2\xcf\x9b\x4f\xf0\xfd\xfe\x8b\x30\xcd\x95\x20\x96\x14\xb7", 32),
  S("\x4e\x3b\xbb\x1f\x7b\x47\x8d\xcf\xe7\x1f\xb6\x31\x63\x15\x19\xa3"
    "\xbc\xa1\x2c\x9a\xef\xca\x16\x12\xbf\xce\x4c\x13\xa8\x62\x64\xd4", 32),
  S("\x76\xe6\x7d\xad\xbc\xdf\x1e\x10\xe1\xb7\x4d\xdc\x60\x8a\xbd\x2f"
    "\x98\xdf\xb1\x6f\xbc\xe7\x52\x77\xb5\x23\x2a\x12\x7f\x20\x87\xef", 32),
  S("\xdd\xb8\x9b\xe4\x03\x80\x9e\x32\x57\x50\xd3\xd2\x63\xcd\x78\x92"
    "\x9c\x29\x42\xb7\x94\x2a\x34\xb7\x7e\x12\x2c\x95\x94\xa7\x4c\x8c", 32),
  S("\x5d\xc9\xda\x79\xa7\x06\x59\xa9\xad\x55\x9c\xb7\x01\xde\xd9\xa2"
    "\xab\x9d\x82\x3a\xad\x2f\x49\x60\xcf\xe3\x70\xef\xf4\x60\x43\x28", 32)
};

// Some paths for this tree.
typedef struct {
  unsigned int leaf;
  unsigned int snapshot;
  unsigned int path_length;
  std::string path[5];
} PathTestVector;

// Generated from ReferenceMerklePath.
PathTestVector sha256_paths[5] = {
  { 0, 0, 1, {
      S("\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
        "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55", 32),
      "", "", "", "" }},
  { 1, 8, 5, {
      S("\x6e\x34\x0b\x9c\xff\xb3\x7a\x98\x9c\xa5\x44\xe6\xbb\x78\x0a\x2c"
        "\x78\x90\x1d\x3f\xb3\x37\x38\x76\x85\x11\xa3\x06\x17\xaf\xa0\x1d", 32),
      S("\x96\xa2\x96\xd2\x24\xf2\x85\xc6\x7b\xee\x93\xc3\x0f\x8a\x30\x91"
        "\x57\xf0\xda\xa3\x5d\xc5\xb8\x7e\x41\x0b\x78\x63\x0a\x09\xcf\xc7", 32),
      S("\x5f\x08\x3f\x0a\x1a\x33\xca\x07\x6a\x95\x27\x98\x32\x58\x0d\xb3"
        "\xe0\xef\x45\x84\xbd\xff\x1f\x54\xc8\xa3\x60\xf5\x0d\xe3\x03\x1e", 32),
      S("\x6b\x47\xaa\xf2\x9e\xe3\xc2\xaf\x9a\xf8\x89\xbc\x1f\xb9\x25\x4d"
        "\xab\xd3\x11\x77\xf1\x62\x32\xdd\x6a\xab\x03\x5c\xa3\x9b\xf6\xe4", 32),
      S("\x5d\xc9\xda\x79\xa7\x06\x59\xa9\xad\x55\x9c\xb7\x01\xde\xd9\xa2"
        "\xab\x9d\x82\x3a\xad\x2f\x49\x60\xcf\xe3\x70\xef\xf4\x60\x43\x28", 32)
    }},
  { 6, 8, 5, {
      S("\x42\x71\xa2\x6b\xe0\xd8\xa8\x4f\x0b\xd5\x4c\x8c\x30\x2e\x7c\xb3"
        "\xa3\xb5\xd1\xfa\x67\x80\xa4\x0b\xcc\xe2\x87\x34\x77\xda\xb6\x58", 32),
      S("\xbc\x1a\x06\x43\xb1\x2e\x4d\x2d\x7c\x77\x91\x8f\x44\xe0\xf4\xf7"
        "\x9a\x83\x8b\x6c\xf9\xec\x5b\x5c\x28\x3e\x1f\x4d\x88\x59\x9e\x6b", 32),
      S("\xca\x85\x4e\xa1\x28\xed\x05\x0b\x41\xb3\x5f\xfc\x1b\x87\xb8\xeb"
        "\x2b\xde\x46\x1e\x9e\x3b\x55\x96\xec\xe6\xb9\xd5\x97\x5a\x0a\xe0", 32),
      S("\xd3\x7e\xe4\x18\x97\x6d\xd9\x57\x53\xc1\xc7\x38\x62\xb9\x39\x8f"
        "\xa2\xa2\xcf\x9b\x4f\xf0\xfd\xfe\x8b\x30\xcd\x95\x20\x96\x14\xb7", 32),
      S("\x5d\xc9\xda\x79\xa7\x06\x59\xa9\xad\x55\x9c\xb7\x01\xde\xd9\xa2"
        "\xab\x9d\x82\x3a\xad\x2f\x49\x60\xcf\xe3\x70\xef\xf4\x60\x43\x28", 32)
    }},
  { 3, 3, 3, {
      S("\x02\x98\xd1\x22\x90\x6d\xcf\xc1\x08\x92\xcb\x53\xa7\x39\x92\xfc"
        "\x5b\x9f\x49\x3e\xa4\xc9\xba\xdb\x27\xb7\x91\xb4\x12\x7a\x7f\xe7", 32),
      S("\xfa\xc5\x42\x03\xe7\xcc\x69\x6c\xf0\xdf\xcb\x42\xc9\x2a\x1d\x9d"
        "\xba\xf7\x0a\xd9\xe6\x21\xf4\xbd\x8d\x98\x66\x2f\x00\xe3\xc1\x25", 32),
      S("\xae\xb6\xbc\xfe\x27\x4b\x70\xa1\x4f\xb0\x67\xa5\xe5\x57\x82\x64"
        "\xdb\x0f\xa9\xb5\x1a\xf5\xe0\xba\x15\x91\x58\xf3\x29\xe0\x6e\x77", 32),
      "", "" }},
  { 2, 5, 5, {
      S("\x96\xa2\x96\xd2\x24\xf2\x85\xc6\x7b\xee\x93\xc3\x0f\x8a\x30\x91"
        "\x57\xf0\xda\xa3\x5d\xc5\xb8\x7e\x41\x0b\x78\x63\x0a\x09\xcf\xc7", 32),
      S("\x6e\x34\x0b\x9c\xff\xb3\x7a\x98\x9c\xa5\x44\xe6\xbb\x78\x0a\x2c"
        "\x78\x90\x1d\x3f\xb3\x37\x38\x76\x85\x11\xa3\x06\x17\xaf\xa0\x1d", 32),
      S("\x5f\x08\x3f\x0a\x1a\x33\xca\x07\x6a\x95\x27\x98\x32\x58\x0d\xb3"
        "\xe0\xef\x45\x84\xbd\xff\x1f\x54\xc8\xa3\x60\xf5\x0d\xe3\x03\x1e", 32),
      S("\xbc\x1a\x06\x43\xb1\x2e\x4d\x2d\x7c\x77\x91\x8f\x44\xe0\xf4\xf7"
        "\x9a\x83\x8b\x6c\xf9\xec\x5b\x5c\x28\x3e\x1f\x4d\x88\x59\x9e\x6b", 32),
      S("\x4e\x3b\xbb\x1f\x7b\x47\x8d\xcf\xe7\x1f\xb6\x31\x63\x15\x19\xa3"
        "\xbc\xa1\x2c\x9a\xef\xca\x16\x12\xbf\xce\x4c\x13\xa8\x62\x64\xd4", 32)
    }}
};

// Get the largest power of two smaller than i.
unsigned int DownToPowerOfTwo(unsigned int i) {
  assert(i >= 2);
  // Find the smallest power of two greater than or equal to i.
  unsigned int split = 1;
  do {
    split <<= 1;
  } while (split < i);

  // Get the largest power of two smaller than i.
  return split >> 1;
}

// Reference implementation of Merkle hash, for cross-checking.
std::string ReferenceMerkleTreeHash(std::string inputs[],
                                    unsigned int input_size,
                                    TreeHasher *treehasher) {
  if (!input_size)
    return treehasher->HashEmpty();
  if (input_size == 1)
    return treehasher->HashLeaf(inputs[0]);

  unsigned int split = DownToPowerOfTwo(input_size);

  return treehasher->HashChildren(
      ReferenceMerkleTreeHash(&inputs[0], split, treehasher),
      ReferenceMerkleTreeHash(&inputs[split], input_size - split, treehasher));
}

// Reference implementation of Merkle paths, for cross-checking.
std::vector<std::string>
ReferenceMerklePath(std::string inputs[], unsigned int input_size,
                    unsigned int leaf, TreeHasher *treehasher, bool add_root) {
  std::vector<std::string> path;
  if (leaf > input_size)
    return path;
  if (leaf == 0) {
    path.push_back(treehasher->HashEmpty());
    return path;
  }

  if (input_size == 1) {
    // Include the leaf itself in the path.
    path.push_back(treehasher->HashLeaf(inputs[0]));
    return path;
  }

  unsigned int split = DownToPowerOfTwo(input_size);

  std::vector<std::string> subpath;
  if (leaf <= split) {
    subpath = ReferenceMerklePath(&inputs[0], split, leaf, treehasher, false);
    path.insert(path.end(), subpath.begin(), subpath.end());
    path.push_back(ReferenceMerkleTreeHash(&inputs[split], input_size - split,
                                           treehasher));
  } else {
    subpath = ReferenceMerklePath(&inputs[split], input_size - split,
                                  leaf - split, treehasher, false);
    path.insert(path.end(), subpath.begin(), subpath.end());
    path.push_back(ReferenceMerkleTreeHash(&inputs[0], split, treehasher));
  }

  if (add_root)
    path.push_back(ReferenceMerkleTreeHash(inputs, input_size, treehasher));
  return path;
}

// Make random root queries and check against the reference hash.
void RootFuzzTest() {
  std::string data[256];
  data[0] = S("\x00", 1);
  for (unsigned int i = 1; i < 256; ++i)
    data[i] = (char)(i);
  TreeHasher treehasher(new Sha256Hasher());

  srand(time(NULL));
  // Repeat test for each tree size in 1...256.
  for (unsigned int tree_size = 1; tree_size < 257; ++tree_size) {
    MerkleTree tree(new Sha256Hasher());
    for (unsigned int j = 0; j < tree_size; ++j)
      tree.AddLeaf(data[j]);
    // Since the tree is evaluated lazily, the order of queries is significant.
    // Generate a random sequence of 8 queries for each tree.
    for (unsigned int j = 0; j < 8; ++j) {
      // A snapshot in the range 0...tree_size.
      unsigned int snapshot = rand() % (tree_size + 1);
      assert(tree.RootAtSnapshot(snapshot) ==
             ReferenceMerkleTreeHash(data, snapshot, &treehasher));
    }
  }
}

// Make random path queries and check against the reference implementation.
void PathFuzzTest() {
  std::string data[256];
  data[0] = S("\x00", 1);
  for (unsigned int i = 1; i < 256; ++i)
    data[i] = (char)(i);
  TreeHasher treehasher(new Sha256Hasher());

  srand(time(NULL));
  // Repeat test for each tree size in 1...256.
  for (unsigned int tree_size = 1; tree_size < 257; ++tree_size) {
    MerkleTree tree(new Sha256Hasher());
    for (unsigned int j = 0; j < tree_size; ++j)
      tree.AddLeaf(data[j]);

    // Since the tree is evaluated lazily, the order of queries is significant.
    // Generate a random sequence of 8 queries for each tree.
    for (unsigned int j = 0; j < 8; ++j) {
      // A snapshot in the range 0... length.
      unsigned int snapshot = rand() % (tree_size + 1);
      // A leaf in the range 0... snapshot.
      unsigned int leaf = rand() % (snapshot + 1);
      assert(tree.PathToRootAtSnapshot(leaf, snapshot) ==
             ReferenceMerklePath(data, snapshot, leaf, &treehasher, true));
    }
  }
}

void RootKatTest() {
  // The first tree: add nodes one by one.
  MerkleTree tree1(new Sha256Hasher());
  assert(tree1.LeafCount() == 0);
  assert(tree1.LevelCount() == 0);
  assert(tree1.CurrentRoot() == sha256_empty_tree_hash);
  for (unsigned int i = 0; i < 8; ++i) {
    tree1.AddLeaf(inputs[i]);
    assert(tree1.LeafCount() == i + 1);
    assert(tree1.LevelCount() == level_counts[i]);
    assert(tree1.CurrentRoot() == sha256_roots[i]);
    assert(tree1.RootAtSnapshot(0) == sha256_empty_tree_hash);
    for (unsigned int j = 0; j <= i; ++j) {
      assert(tree1.RootAtSnapshot(j + 1) == sha256_roots[j]);
    }

    for (unsigned int j = i + 1; j < 8; ++j) {
      assert(tree1.RootAtSnapshot(j + 1) == "");
    }
  }

  // The second tree: add all nodes at once.
  MerkleTree tree2(new Sha256Hasher());
  for (unsigned int i = 0; i < 8; ++i) {
    tree2.AddLeaf(inputs[i]);
  }
  assert(tree2.LeafCount() == 8);
  assert(tree2.LevelCount() == level_counts[7]);
  assert(tree2.CurrentRoot() == sha256_roots[7]);

  // The third tree: add nodes in two chunks.
  MerkleTree tree3(new Sha256Hasher());
  // Add three nodes.
  for (unsigned int i = 0; i < 3; ++i) {
    tree3.AddLeaf(inputs[i]);
  }
  assert(tree3.LeafCount() == 3);
  assert(tree3.LevelCount() == level_counts[2]);
  assert(tree3.CurrentRoot() == sha256_roots[2]);
  // Add the remaining nodes.
  for (unsigned int i = 3; i < 8; ++i) {
    tree3.AddLeaf(inputs[i]);
  }
  assert(tree3.LeafCount() == 8);
  assert(tree3.LevelCount() == level_counts[7]);
  assert(tree3.CurrentRoot() == sha256_roots[7]);
}

void PathKatTest() {
  // First tree: build in one go.
  MerkleTree tree1(new Sha256Hasher());
  for (unsigned int i = 0; i < 8; ++i) {
    tree1.AddLeaf(inputs[i]);
  }
  assert(tree1.LeafCount() == 8);
  assert(tree1.CurrentRoot() == sha256_roots[7]);

  assert(tree1.PathToCurrentRoot(9).empty());
  for (unsigned int i = 0; i < 5; ++i) {
    std::vector<std::string> path = tree1.PathToRootAtSnapshot(
        sha256_paths[i].leaf, sha256_paths[i].snapshot);
    assert(path.size() == sha256_paths[i].path_length);
    for (unsigned int j = 0; j < path.size(); ++j) {
      assert(path[j] == sha256_paths[i].path[j]);
    }
  }

  // Second tree: build incrementally.
  MerkleTree tree2(new Sha256Hasher());
  assert(tree2.PathToCurrentRoot(0) == tree1.PathToRootAtSnapshot(0, 0));
  assert(tree2.PathToCurrentRoot(1).empty());
  for (unsigned int i = 0; i < 8; ++i) {
    tree2.AddLeaf(inputs[i]);
    for(unsigned int j = 0; j <= i + 1; ++j) {
      assert(tree1.PathToRootAtSnapshot(j, i + 1) ==
             tree2.PathToCurrentRoot(j));
    }
    for(unsigned int j = i + 2; j <= 9; ++j) {
      assert(tree1.PathToRootAtSnapshot(j, i + 1).empty());
    }
  }
}

void MerkleTreeTest() {
  std::cout << "Checking test vectors... ";
  RootKatTest();
  PathKatTest();
  std::cout << "OK\n";
  std::cout << "Testing against reference implementation... ";
  // Randomized tests.
  RootFuzzTest();
  PathFuzzTest();
  std::cout << "OK\n";
}

#undef S

} // namespace

int main(int, char**) {
  std::cout << "Testing MerkleTrees with SHA-256\n";
  MerkleTreeTest();
  std::cout << "PASS\n";
  return 0;
}
