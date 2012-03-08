// Opened for readability review.
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <time.h>
#include <vector>

#include "MerkleTree.h"
#include "MerkleVerifier.h"
#include "SerialHasher.h"
#include "TreeHasher.h"

namespace {

////////////////////////////////////////////////////////////////////////////////
//                          REFERENCE IMPLEMENTATIONS                         //
////////////////////////////////////////////////////////////////////////////////
// Get the largest power of two smaller than i.
int DownToPowerOfTwo(int i) {
  assert(i >= 2);
  // Find the smallest power of two greater than or equal to i.
  int split = 1;
  do {
    split <<= 1;
  } while (split < i);

  // Get the largest power of two smaller than i.
  return split >> 1;
}

// Reference implementation of Merkle hash, for cross-checking.
std::string ReferenceMerkleTreeHash(std::string inputs[], int input_size,
                                    TreeHasher *treehasher) {
  if (!input_size)
    return treehasher->HashEmpty();
  if (input_size == 1)
    return treehasher->HashLeaf(inputs[0]);

  const int split = DownToPowerOfTwo(input_size);

  return treehasher->HashChildren(
      ReferenceMerkleTreeHash(&inputs[0], split, treehasher),
      ReferenceMerkleTreeHash(&inputs[split], input_size - split, treehasher));
}

// Reference implementation of Merkle paths. Path from leaf to root,
// excluding the leaf and root themselves.
std::vector<std::string>
ReferenceMerklePath(std::string inputs[], int input_size, int leaf,
                    TreeHasher *treehasher) {
  std::vector<std::string> path;
  if (leaf > input_size || leaf == 0)
    return path;

  if (input_size == 1)
    return path;

  const int split = DownToPowerOfTwo(input_size);

  std::vector<std::string> subpath;
  if (leaf <= split) {
    subpath = ReferenceMerklePath(&inputs[0], split, leaf, treehasher);
    path.insert(path.end(), subpath.begin(), subpath.end());
    path.push_back(ReferenceMerkleTreeHash(&inputs[split], input_size - split,
                                           treehasher));
  } else {
    subpath = ReferenceMerklePath(&inputs[split], input_size - split,
                                  leaf - split, treehasher);
    path.insert(path.end(), subpath.begin(), subpath.end());
    path.push_back(ReferenceMerkleTreeHash(&inputs[0], split, treehasher));
  }

  return path;
}

// Reference implementation of snapshot consistency.
// Call with have_root1 = true.
std::vector<std::string>
ReferenceSnapshotConsistency(std::string inputs[], int snapshot2,
                             int snapshot1, TreeHasher *treehasher,
                             bool have_root1) {
  std::vector<std::string> proof;
  if (snapshot1 == 0 || snapshot1 > snapshot2)
    return proof;
  if (snapshot1 == snapshot2) {
    // Consistency proof for two equal subtrees is empty.
    if (!have_root1)
      // Record the hash of this subtree unless it's the root for which
      // the proof was originally requested. (This happens when the snapshot1
      // tree is balanced.)
      proof.push_back(ReferenceMerkleTreeHash(inputs, snapshot1, treehasher));
    return proof;
  }

  // 0 < snapshot1 < snapshot2
  const int split = DownToPowerOfTwo(snapshot2);

  std::vector<std::string> subproof;
  if (snapshot1 <= split) {
    // Root of snapshot1 is in the left subtree of snapshot2.
    // Prove that the left subtrees are consistent.
    subproof = ReferenceSnapshotConsistency(inputs, split, snapshot1,
                                            treehasher, have_root1);
    proof.insert(proof.end(), subproof.begin(), subproof.end());
    // Record the hash of the right subtree (only present in snapshot2).
    proof.push_back(ReferenceMerkleTreeHash(&inputs[split], snapshot2 - split,
                                            treehasher));
  } else {
    // Snapshot1 root is at the same level as snapshot2 root.
    // Prove that the right subtrees are consistent. The right subtree
    // doesn't contain the root of snapshot1, so set have_root1 = false.
    subproof = ReferenceSnapshotConsistency(&inputs[split], snapshot2 - split,
                                            snapshot1 - split, treehasher,
                                            false);
    proof.insert(proof.end(), subproof.begin(), subproof.end());
    // Record the hash of the left subtree (equal in both trees).
    proof.push_back(ReferenceMerkleTreeHash(&inputs[0], split, treehasher));
  }
  return proof;
}

////////////////////////////////////////////////////////////////////////////////
//              FUZZ TESTS AGAINST REFERENCE IMPLEMENTATIONS                  //
////////////////////////////////////////////////////////////////////////////////

// Make random root queries and check against the reference hash.
void RootFuzzTest() {
  std::string data[256];
  for (int i = 0; i < 256; ++i)
    data[i] = std::string(1, static_cast<char>(i));
  TreeHasher treehasher(new Sha256Hasher());

  // Repeat test for each tree size in 1...256.
  for (int tree_size = 1; tree_size <= 256; ++tree_size) {
    MerkleTree tree(new Sha256Hasher());
    for (int j = 0; j < tree_size; ++j)
      tree.AddLeaf(data[j]);
    // Since the tree is evaluated lazily, the order of queries is significant.
    // Generate a random sequence of 8 queries for each tree.
    for (int j = 0; j < 8; ++j) {
      // A snapshot in the range 0...tree_size.
      const int snapshot = rand() % (tree_size + 1);
      assert(tree.RootAtSnapshot(snapshot) ==
             ReferenceMerkleTreeHash(data, snapshot, &treehasher));
    }
  }
}

// Make random path queries and check against the reference implementation.
void PathFuzzTest() {
  std::string data[256];
  for (int i = 0; i < 256; ++i)
    data[i] = std::string(1, static_cast<char>(i));
  TreeHasher treehasher(new Sha256Hasher());

  // Repeat test for each tree size in 1...256.
  for (int tree_size = 1; tree_size <= 256; ++tree_size) {
    MerkleTree tree(new Sha256Hasher());
    for (int j = 0; j < tree_size; ++j)
      tree.AddLeaf(data[j]);

    // Since the tree is evaluated lazily, the order of queries is significant.
    // Generate a random sequence of 8 queries for each tree.
    for (int j = 0; j < 8; ++j) {
      // A snapshot in the range 0... length.
      const int snapshot = rand() % (tree_size + 1);
      // A leaf in the range 0... snapshot.
      const int leaf = rand() % (snapshot + 1);
      assert(tree.PathToRootAtSnapshot(leaf, snapshot) ==
             ReferenceMerklePath(data, snapshot, leaf, &treehasher));
    }
  }
}

// Make random proof queries and check against the reference implementation.
void ConsistencyFuzzTest() {
  std::string data[256];
  for (int i = 0; i < 256; ++i)
    data[i] = std::string(1, static_cast<char>(i));
  TreeHasher treehasher(new Sha256Hasher());

  // Repeat test for each tree size in 1...256.
  for (int tree_size = 1; tree_size <= 256; ++tree_size) {
    MerkleTree tree(new Sha256Hasher());
    for (int j = 0; j < tree_size; ++j)
      tree.AddLeaf(data[j]);

    // Since the tree is evaluated lazily, the order of queries is significant.
    // Generate a random sequence of 8 queries for each tree.
    for (int j = 0; j < 8; ++j) {
      // A snapshot in the range 0... length.
      const int snapshot2 = rand() % (tree_size + 1);
      // A snapshot in the range 0... snapshot.
      const int snapshot1 = rand() % (snapshot2 + 1);
      assert(tree.SnapshotConsistency(snapshot1, snapshot2) ==
             ReferenceSnapshotConsistency(data, snapshot2, snapshot1,
                                          &treehasher, true));
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
//                          KNOWN ANSWER TESTS                                //
////////////////////////////////////////////////////////////////////////////////

typedef struct {
  const char *str;
  int length;
} TestVector;

// A slightly shorter notation for constructing binary blobs from test vectors.
#define S(t) std::string(t.str, t.length)

// The hash of an empty tree is the hash of the empty string.
// (see SerialHasherTest and http://csrc.nist.gov/groups/STM/cavp/)
const TestVector kSHA256EmptyTreeHash = {
  "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
  "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55", 32
};

// Inputs to the reference tree, which has eight leaves.
const TestVector kInputs[8] = {
  { "", 0 },
  { "\x00", 1 },
  { "\x10", 1 },
  { "\x20\x21", 2 },
  { "\x30\x31", 2 },
  { "\x40\x41\x42\x43", 4 },
  { "\x50\x51\x52\x53\x54\x55\x56\x57", 8 },
  { "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f", 16 },
};

// Level counts for number of leaves in [1, 8]
const size_t kLevelCounts[8] = {1, 2, 3, 3, 4, 4, 4, 4};

// Incremental roots from building the reference tree from inputs leaf-by-leaf.
// Generated from ReferenceMerkleTreeHash.
const TestVector kSHA256Roots[8] = {
  { "\x6e\x34\x0b\x9c\xff\xb3\x7a\x98\x9c\xa5\x44\xe6\xbb\x78\x0a\x2c"
    "\x78\x90\x1d\x3f\xb3\x37\x38\x76\x85\x11\xa3\x06\x17\xaf\xa0\x1d", 32 },
  { "\xfa\xc5\x42\x03\xe7\xcc\x69\x6c\xf0\xdf\xcb\x42\xc9\x2a\x1d\x9d"
    "\xba\xf7\x0a\xd9\xe6\x21\xf4\xbd\x8d\x98\x66\x2f\x00\xe3\xc1\x25", 32 },
  { "\xae\xb6\xbc\xfe\x27\x4b\x70\xa1\x4f\xb0\x67\xa5\xe5\x57\x82\x64"
    "\xdb\x0f\xa9\xb5\x1a\xf5\xe0\xba\x15\x91\x58\xf3\x29\xe0\x6e\x77", 32 },
  { "\xd3\x7e\xe4\x18\x97\x6d\xd9\x57\x53\xc1\xc7\x38\x62\xb9\x39\x8f"
    "\xa2\xa2\xcf\x9b\x4f\xf0\xfd\xfe\x8b\x30\xcd\x95\x20\x96\x14\xb7", 32 },
  { "\x4e\x3b\xbb\x1f\x7b\x47\x8d\xcf\xe7\x1f\xb6\x31\x63\x15\x19\xa3"
    "\xbc\xa1\x2c\x9a\xef\xca\x16\x12\xbf\xce\x4c\x13\xa8\x62\x64\xd4", 32 },
  { "\x76\xe6\x7d\xad\xbc\xdf\x1e\x10\xe1\xb7\x4d\xdc\x60\x8a\xbd\x2f"
    "\x98\xdf\xb1\x6f\xbc\xe7\x52\x77\xb5\x23\x2a\x12\x7f\x20\x87\xef", 32 },
  { "\xdd\xb8\x9b\xe4\x03\x80\x9e\x32\x57\x50\xd3\xd2\x63\xcd\x78\x92"
    "\x9c\x29\x42\xb7\x94\x2a\x34\xb7\x7e\x12\x2c\x95\x94\xa7\x4c\x8c", 32 },
  { "\x5d\xc9\xda\x79\xa7\x06\x59\xa9\xad\x55\x9c\xb7\x01\xde\xd9\xa2"
    "\xab\x9d\x82\x3a\xad\x2f\x49\x60\xcf\xe3\x70\xef\xf4\x60\x43\x28", 32 }
};

void RootKatTest() {
  // The first tree: add nodes one by one.
  MerkleTree tree1(new Sha256Hasher());
  assert(tree1.LeafCount() == 0);
  assert(tree1.LevelCount() == 0);
  assert(tree1.CurrentRoot() == S(kSHA256EmptyTreeHash));
  for (size_t i = 0; i < 8; ++i) {
    tree1.AddLeaf(S(kInputs[i]));
    assert(tree1.LeafCount() == i + 1);
    assert(tree1.LevelCount() == kLevelCounts[i]);
    assert(tree1.CurrentRoot() == S(kSHA256Roots[i]));
    assert(tree1.RootAtSnapshot(0) == S(kSHA256EmptyTreeHash));
    for (size_t j = 0; j <= i; ++j) {
      assert(tree1.RootAtSnapshot(j + 1) == S(kSHA256Roots[j]));
    }

    for (size_t j = i + 1; j < 8; ++j) {
      assert(tree1.RootAtSnapshot(j + 1) == "");
    }
  }

  // The second tree: add all nodes at once.
  MerkleTree tree2(new Sha256Hasher());
  for (int i = 0; i < 8; ++i) {
    tree2.AddLeaf(S(kInputs[i]));
  }
  assert(tree2.LeafCount() == 8);
  assert(tree2.LevelCount() == kLevelCounts[7]);
  assert(tree2.CurrentRoot() == S(kSHA256Roots[7]));

  // The third tree: add nodes in two chunks.
  MerkleTree tree3(new Sha256Hasher());
  // Add three nodes.
  for (int i = 0; i < 3; ++i) {
    tree3.AddLeaf(S(kInputs[i]));
  }
  assert(tree3.LeafCount() == 3);
  assert(tree3.LevelCount() == kLevelCounts[2]);
  assert(tree3.CurrentRoot() == S(kSHA256Roots[2]));
  // Add the remaining nodes.
  for (int i = 3; i < 8; ++i) {
    tree3.AddLeaf(S(kInputs[i]));
  }
  assert(tree3.LeafCount() == 8);
  assert(tree3.LevelCount() == kLevelCounts[7]);
  assert(tree3.CurrentRoot() == S(kSHA256Roots[7]));
}

// Some paths for the reference tree.
typedef struct {
  int leaf;
  int snapshot;
  int path_length;
  TestVector path[3];
} PathTestVector;

// Generated from ReferenceMerklePath.
const PathTestVector kSHA256Paths[6] = {
  { 0, 0, 0, { { "", 0 }, { "", 0 }, { "", 0 }}},
  { 1, 1, 0, { { "", 0 }, { "", 0 }, { "", 0 }}},
  { 1, 8, 3, {
      { "\x96\xa2\x96\xd2\x24\xf2\x85\xc6\x7b\xee\x93\xc3\x0f\x8a\x30\x91"
        "\x57\xf0\xda\xa3\x5d\xc5\xb8\x7e\x41\x0b\x78\x63\x0a\x09\xcf\xc7",
        32 },
      { "\x5f\x08\x3f\x0a\x1a\x33\xca\x07\x6a\x95\x27\x98\x32\x58\x0d\xb3"
        "\xe0\xef\x45\x84\xbd\xff\x1f\x54\xc8\xa3\x60\xf5\x0d\xe3\x03\x1e",
        32 },
      { "\x6b\x47\xaa\xf2\x9e\xe3\xc2\xaf\x9a\xf8\x89\xbc\x1f\xb9\x25\x4d"
        "\xab\xd3\x11\x77\xf1\x62\x32\xdd\x6a\xab\x03\x5c\xa3\x9b\xf6\xe4",
        32 }
    }},
  { 6, 8, 3, {
      { "\xbc\x1a\x06\x43\xb1\x2e\x4d\x2d\x7c\x77\x91\x8f\x44\xe0\xf4\xf7"
        "\x9a\x83\x8b\x6c\xf9\xec\x5b\x5c\x28\x3e\x1f\x4d\x88\x59\x9e\x6b",
        32 },
      { "\xca\x85\x4e\xa1\x28\xed\x05\x0b\x41\xb3\x5f\xfc\x1b\x87\xb8\xeb"
        "\x2b\xde\x46\x1e\x9e\x3b\x55\x96\xec\xe6\xb9\xd5\x97\x5a\x0a\xe0",
        32 },
      { "\xd3\x7e\xe4\x18\x97\x6d\xd9\x57\x53\xc1\xc7\x38\x62\xb9\x39\x8f"
        "\xa2\xa2\xcf\x9b\x4f\xf0\xfd\xfe\x8b\x30\xcd\x95\x20\x96\x14\xb7",
        32 }
    }},
  { 3, 3, 1, {
      { "\xfa\xc5\x42\x03\xe7\xcc\x69\x6c\xf0\xdf\xcb\x42\xc9\x2a\x1d\x9d"
        "\xba\xf7\x0a\xd9\xe6\x21\xf4\xbd\x8d\x98\x66\x2f\x00\xe3\xc1\x25",
        32 },
      { "", 0 }, { "", 0 }
    }},
  { 2, 5, 3, {
      { "\x6e\x34\x0b\x9c\xff\xb3\x7a\x98\x9c\xa5\x44\xe6\xbb\x78\x0a\x2c"
        "\x78\x90\x1d\x3f\xb3\x37\x38\x76\x85\x11\xa3\x06\x17\xaf\xa0\x1d",
        32 },
      { "\x5f\x08\x3f\x0a\x1a\x33\xca\x07\x6a\x95\x27\x98\x32\x58\x0d\xb3"
        "\xe0\xef\x45\x84\xbd\xff\x1f\x54\xc8\xa3\x60\xf5\x0d\xe3\x03\x1e",
        32 },
      { "\xbc\x1a\x06\x43\xb1\x2e\x4d\x2d\x7c\x77\x91\x8f\x44\xe0\xf4\xf7"
        "\x9a\x83\x8b\x6c\xf9\xec\x5b\x5c\x28\x3e\x1f\x4d\x88\x59\x9e\x6b",
        32 }
    }}
};

void PathKatTest() {
  // First tree: build in one go.
  MerkleTree tree1(new Sha256Hasher());
  for (int i = 0; i < 8; ++i) {
    tree1.AddLeaf(S(kInputs[i]));
  }
  assert(tree1.LeafCount() == 8);
  assert(tree1.CurrentRoot() == S(kSHA256Roots[7]));

  assert(tree1.PathToCurrentRoot(9).empty());
  for (int i = 0; i < 6; ++i) {
    std::vector<std::string> path = tree1.PathToRootAtSnapshot(
        kSHA256Paths[i].leaf, kSHA256Paths[i].snapshot);
    std::vector<std::string> kat_path;
    for (int j = 0; j < kSHA256Paths[i].path_length; ++j)
      kat_path.push_back(S(kSHA256Paths[i].path[j]));
    assert(path == kat_path);
  }

  // Second tree: build incrementally.
  MerkleTree tree2(new Sha256Hasher());
  assert(tree2.PathToCurrentRoot(0) == tree1.PathToRootAtSnapshot(0, 0));
  assert(tree2.PathToCurrentRoot(1).empty());
  for (int i = 0; i < 8; ++i) {
    tree2.AddLeaf(S(kInputs[i]));
    for(int j = 0; j <= i + 1; ++j) {
      assert(tree1.PathToRootAtSnapshot(j, i + 1) ==
             tree2.PathToCurrentRoot(j));
    }
    for(int j = i + 2; j <= 9; ++j) {
      assert(tree1.PathToRootAtSnapshot(j, i + 1).empty());
    }
  }
}

typedef struct {
  int snapshot1;
  int snapshot2;
  int proof_length;
  TestVector proof[3];
} ProofTestVector;

// Generated from ReferenceSnapshotConsistency.
const ProofTestVector kSHA256Proofs[4] = {
  { 1, 1, 0, { { "", 0 }, { "", 0 }, { "", 0 } }},
  { 1, 8, 3, {
      { "\x96\xa2\x96\xd2\x24\xf2\x85\xc6\x7b\xee\x93\xc3\x0f\x8a\x30\x91"
        "\x57\xf0\xda\xa3\x5d\xc5\xb8\x7e\x41\x0b\x78\x63\x0a\x09\xcf\xc7",
        32 },
      { "\x5f\x08\x3f\x0a\x1a\x33\xca\x07\x6a\x95\x27\x98\x32\x58\x0d\xb3"
        "\xe0\xef\x45\x84\xbd\xff\x1f\x54\xc8\xa3\x60\xf5\x0d\xe3\x03\x1e",
        32 },
      { "\x6b\x47\xaa\xf2\x9e\xe3\xc2\xaf\x9a\xf8\x89\xbc\x1f\xb9\x25\x4d"
        "\xab\xd3\x11\x77\xf1\x62\x32\xdd\x6a\xab\x03\x5c\xa3\x9b\xf6\xe4",
        32 }
    }},
  { 6, 8, 3, {
      { "\x0e\xbc\x5d\x34\x37\xfb\xe2\xdb\x15\x8b\x9f\x12\x6a\x1d\x11\x8e"
        "\x30\x81\x81\x03\x1d\x0a\x94\x9f\x8d\xed\xed\xeb\xc5\x58\xef\x6a",
        32 },
      { "\xca\x85\x4e\xa1\x28\xed\x05\x0b\x41\xb3\x5f\xfc\x1b\x87\xb8\xeb"
        "\x2b\xde\x46\x1e\x9e\x3b\x55\x96\xec\xe6\xb9\xd5\x97\x5a\x0a\xe0",
        32 },
      { "\xd3\x7e\xe4\x18\x97\x6d\xd9\x57\x53\xc1\xc7\x38\x62\xb9\x39\x8f"
        "\xa2\xa2\xcf\x9b\x4f\xf0\xfd\xfe\x8b\x30\xcd\x95\x20\x96\x14\xb7",
        32 }
    }},
  { 2, 5, 2, {
      { "\x5f\x08\x3f\x0a\x1a\x33\xca\x07\x6a\x95\x27\x98\x32\x58\x0d\xb3"
        "\xe0\xef\x45\x84\xbd\xff\x1f\x54\xc8\xa3\x60\xf5\x0d\xe3\x03\x1e",
        32 },
      { "\xbc\x1a\x06\x43\xb1\x2e\x4d\x2d\x7c\x77\x91\x8f\x44\xe0\xf4\xf7"
        "\x9a\x83\x8b\x6c\xf9\xec\x5b\x5c\x28\x3e\x1f\x4d\x88\x59\x9e\x6b",
        32 },
      { "", 0 } }}
};

void ConsistencyKatTest() {
  MerkleTree tree1(new Sha256Hasher());
  for (int i = 0; i < 8; ++i) {
    tree1.AddLeaf(S(kInputs[i]));
  }
  assert(tree1.LeafCount() == 8);
  assert(tree1.CurrentRoot() == S(kSHA256Roots[7]));

  for (int i = 0; i < 4; ++i) {
    std::vector<std::string> proof = tree1.SnapshotConsistency(
        kSHA256Proofs[i].snapshot1, kSHA256Proofs[i].snapshot2);
    std::vector<std::string> kat_proof;
    for (int j = 0; j < kSHA256Proofs[i].proof_length; ++j)
      kat_proof.push_back(S(kSHA256Proofs[i].proof[j]));
    assert(proof == kat_proof);
  }
}

////////////////////////////////////////////////////////////////////////////////
//                          VERIFICATION TESTS                                //
////////////////////////////////////////////////////////////////////////////////

void VerifierCheck(int leaf, int tree_size,
                   const std::vector<std::string> &path,
                   const std::string &root,
                   const std::string &data, MerkleVerifier *verifier) {
  // Verify the original path.
  assert(verifier->RootFromPath(leaf, tree_size, path, data) == root);
  assert(verifier->VerifyPath(leaf, tree_size, path, root, data));

  // Wrong leaf index.
  assert(!verifier->VerifyPath(leaf - 1, tree_size, path, root, data));
  assert(!verifier->VerifyPath(leaf + 1, tree_size, path, root, data));
  assert(!verifier->VerifyPath(leaf ^ 2, tree_size, path, root, data));

  // Wrong tree height.
  assert(!verifier->VerifyPath(leaf, tree_size * 2, path, root, data));
  assert(!verifier->VerifyPath(leaf, tree_size / 2, path, root, data));

  // Wrong leaf.
  assert(!verifier->VerifyPath(leaf, tree_size, path, root, "WrongLeaf"));

  // Wrong root.
  assert(!verifier->VerifyPath(leaf, tree_size, path,
                               S(kSHA256EmptyTreeHash), data));

  // Wrong paths.
  std::vector<std::string> wrong_path;

  // Modify a single element on the path.
  for (size_t j = 0; j < path.size(); ++j) {
    wrong_path = path;
    wrong_path[j] = S(kSHA256EmptyTreeHash);
    assert(!verifier->VerifyPath(leaf, tree_size, wrong_path, root, data));
  }

  // Add garbage at the end of the path.
  wrong_path = path;
  wrong_path.push_back("");
  assert(!verifier->VerifyPath(leaf, tree_size, wrong_path, root, data));
  wrong_path.pop_back();

  wrong_path.push_back(root);
  assert(!verifier->VerifyPath(leaf, tree_size, wrong_path, root, data));
  wrong_path.pop_back();

  // Remove a node from the end.
  if (!wrong_path.empty()) {
    wrong_path.pop_back();
    assert(!verifier->VerifyPath(leaf, tree_size, wrong_path, root, data));
  }

  // Add garbage in the beginning of the path.
  wrong_path.clear();
  wrong_path.push_back("");
  wrong_path.insert(wrong_path.end(), path.begin(), path.end());
  assert(!verifier->VerifyPath(leaf, tree_size, wrong_path, root, data));

  wrong_path[0] = root;
  assert(!verifier->VerifyPath(leaf, tree_size, wrong_path, root, data));
}

void VerifierConsistencyCheck(int snapshot1, int snapshot2,
                              const std::string &root1,
                              const std::string &root2,
                              const std::vector<std::string> &proof,
                              MerkleVerifier *verifier) {
  // Verify the original consistency proof.
  assert(verifier->VerifyConsistency(snapshot1, snapshot2, root1, root2,
                                     proof));

  if (proof.empty())
    // For simplicity test only non-trivial proofs that have root1 != root2
    // snapshot1 != 0 and snapshot1 != snapshot2.
    return;

  // Wrong snapshot index.
  assert(!verifier->VerifyConsistency(snapshot1 - 1, snapshot2, root1, root2,
                                     proof));
  assert(!verifier->VerifyConsistency(snapshot1 + 1, snapshot2, root1, root2,
                                     proof));
  assert(!verifier->VerifyConsistency(snapshot1 ^ 2, snapshot2, root1, root2,
                                     proof));

  // Wrong tree height.
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2 * 2, root1, root2,
                                     proof));
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2 / 2, root1, root2,
                                     proof));

  // Wrong root.
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root1, "WrongRoot",
                                      proof));
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, "WrongRoot", root2,
                                      proof));
  // Swap roots.
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root2, root1,
                                      proof));

  // Wrong proofs.
  std::vector<std::string> wrong_proof;
  // Empty proof.
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root1, root2,
                                      wrong_proof));

  // Modify a single element in the proof.
  for (size_t j = 0; j < proof.size(); ++j) {
    wrong_proof = proof;
    wrong_proof[j] = S(kSHA256EmptyTreeHash);
    assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root1, root2,
                                        wrong_proof));
  }

  // Add garbage at the end of the proof.
  wrong_proof = proof;
  wrong_proof.push_back("");
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root1, root2,
                                      wrong_proof));
  wrong_proof.pop_back();

  wrong_proof.push_back(proof.back());
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root1, root2,
                                      wrong_proof));
  wrong_proof.pop_back();

  // Remove a node from the end.
  wrong_proof.pop_back();
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root1, root2,
                                      wrong_proof));

  // Add garbage in the beginning of the proof.
  wrong_proof.clear();
  wrong_proof.push_back("");
  wrong_proof.insert(wrong_proof.end(), proof.begin(), proof.end());
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root1, root2,
                                      wrong_proof));

  wrong_proof[0] = proof[0];
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root1, root2,
                                      wrong_proof));
}

void VerifierTest() {
  MerkleVerifier verifier(new Sha256Hasher());
  std::vector<std::string> path;
  // Various invalid paths.
  assert(!verifier.VerifyPath(0, 0, path, "", ""));
  assert(!verifier.VerifyPath(0, 1, path, "", ""));
  assert(!verifier.VerifyPath(1, 0, path, "", ""));
  assert(!verifier.VerifyPath(2, 1, path, "", ""));

  assert(!verifier.VerifyPath(0, 0, path, S(kSHA256EmptyTreeHash), ""));
  assert(!verifier.VerifyPath(0, 1, path, S(kSHA256EmptyTreeHash), ""));
  assert(!verifier.VerifyPath(1, 0, path, S(kSHA256EmptyTreeHash), ""));
  assert(!verifier.VerifyPath(2, 1, path, S(kSHA256EmptyTreeHash), ""));

  // Known good paths.
  // i = 0 is an invalid path.
  for (int i = 1; i < 6; ++i) {
    // Construct the path.
    path.clear();
    for (int j = 0; j < kSHA256Paths[i].path_length; ++j)
      path.push_back(S(kSHA256Paths[i].path[j]));
    VerifierCheck(kSHA256Paths[i].leaf, kSHA256Paths[i].snapshot,
                  path, S(kSHA256Roots[kSHA256Paths[i].snapshot - 1]),
                  S(kInputs[kSHA256Paths[i].leaf - 1]), &verifier);
  }

  // More tests with reference path generator.
  std::string data[128];
  for (int i = 0; i < 128; ++i)
    data[i] = std::string(1, static_cast<char>(i));
  TreeHasher treehasher(new Sha256Hasher());

  std::string root;
  // Repeat test for each tree size in 1...128.
  for (int tree_size = 1; tree_size <= 128; ++tree_size) {
    // Repeat for each leaf in range.
    for (int leaf = 1; leaf <= tree_size; ++leaf) {
      path = ReferenceMerklePath(data, tree_size, leaf, &treehasher);
      root = ReferenceMerkleTreeHash(data, tree_size, &treehasher);
      VerifierCheck(leaf, tree_size, path, root, data[leaf - 1], &verifier);
    }
  }

  std::vector<std::string> proof;
  std::string root1;
  std::string root2;
  // Snapshots that are always consistent.
  assert(verifier.VerifyConsistency(0, 0, root1, root2, proof));
  assert(verifier.VerifyConsistency(0, 1, root1, root2, proof));
  assert(verifier.VerifyConsistency(1, 1, root1, root2, proof));

  // Invalid consistency proofs.
  // Time travel to the past.
  assert(!verifier.VerifyConsistency(1, 0, root1, root2, proof));
  assert(!verifier.VerifyConsistency(2, 1, root1, root2, proof));
  // Empty proof.
  assert(!verifier.VerifyConsistency(1, 2, root1, root2, proof));

  root1 = S(kSHA256EmptyTreeHash);
  // Roots don't match.
  assert(!verifier.VerifyConsistency(0, 0, root1, root2, proof));
  assert(!verifier.VerifyConsistency(1, 1, root1, root2, proof));
  // Roots match but the proof is not empty.
  root2 = S(kSHA256EmptyTreeHash);
  proof.push_back(S(kSHA256EmptyTreeHash));
  assert(!verifier.VerifyConsistency(0, 0, root1, root2, proof));
  assert(!verifier.VerifyConsistency(0, 1, root1, root2, proof));
  assert(!verifier.VerifyConsistency(1, 1, root1, root2, proof));

  // Known good proofs.
  for (int i = 0; i < 4; ++i) {
    proof.clear();
    for (int j = 0; j < kSHA256Proofs[i].proof_length; ++j)
      proof.push_back(S(kSHA256Proofs[i].proof[j]));
    const int snapshot1 = kSHA256Proofs[i].snapshot1;
    const int snapshot2 = kSHA256Proofs[i].snapshot2;
    VerifierConsistencyCheck(snapshot1, snapshot2,
                             S(kSHA256Roots[snapshot1 - 1]),
                             S(kSHA256Roots[snapshot2 - 1]),
                             proof, &verifier);
  }

  // More tests with reference proof generator.
  // Repeat test for each tree size in 1...128.
  for (int tree_size = 1; tree_size <= 128; ++tree_size) {
    root2 = ReferenceMerkleTreeHash(data, tree_size, &treehasher);
    // Repeat for each snapshot in range.
    for (int snapshot = 1; snapshot <= tree_size; ++snapshot) {
      proof = ReferenceSnapshotConsistency(data, tree_size, snapshot,
                                           &treehasher, true);
      root1 = ReferenceMerkleTreeHash(data, snapshot, &treehasher);
      VerifierConsistencyCheck(snapshot, tree_size, root1, root2, proof,
                               &verifier);
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

// Run all tests.
void MerkleTreeTest() {
  printf("Checking test vectors... ");
  RootKatTest();
  PathKatTest();
  ConsistencyKatTest();
  printf("OK\n");
  printf("Testing against reference implementation... ");
  // Randomized tests.
  srand(time(NULL));
  RootFuzzTest();
  PathFuzzTest();
  ConsistencyFuzzTest();
  printf("OK\n");
  printf("Testing verification... ");
  VerifierTest();
  printf("OK\n");
}

#undef S

} // namespace

int main(int, char**) {
  printf("Testing MerkleTrees with SHA-256\n");
  MerkleTreeTest();
  printf("PASS\n");
  return 0;
}
