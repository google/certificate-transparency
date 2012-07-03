#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <time.h>
#include <vector>

#include "../include/types.h"
#include "../util/util.h"
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
bstring ReferenceMerkleTreeHash(bstring inputs[], int input_size,
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
std::vector<bstring>
ReferenceMerklePath(bstring inputs[], int input_size, int leaf,
                    TreeHasher *treehasher) {
  std::vector<bstring> path;
  if (leaf > input_size || leaf == 0)
    return path;

  if (input_size == 1)
    return path;

  const int split = DownToPowerOfTwo(input_size);

  std::vector<bstring> subpath;
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
std::vector<bstring>
ReferenceSnapshotConsistency(bstring inputs[], int snapshot2,
                             int snapshot1, TreeHasher *treehasher,
                             bool have_root1) {
  std::vector<bstring> proof;
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

  std::vector<bstring> subproof;
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
  bstring data[256];
  for (int i = 0; i < 256; ++i)
    data[i] = bstring(1, i);
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
  bstring data[256];
  for (int i = 0; i < 256; ++i)
    data[i] = bstring(1, i);
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
  bstring data[256];
  for (int i = 0; i < 256; ++i)
    data[i] = bstring(1, i);
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
  int length_bytes;
} TestVector;

// A slightly shorter notation for constructing binary blobs from test vectors.
#define S(t) util::BinaryString(std::string(t.str, 2 * t.length_bytes))

// The hash of an empty tree is the hash of the empty string.
// (see SerialHasherTest and http://csrc.nist.gov/groups/STM/cavp/)
const TestVector kSHA256EmptyTreeHash = {
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32
};

// Inputs to the reference tree, which has eight leaves.
const TestVector kInputs[8] = {
  { "", 0 },
  { "00", 1 },
  { "10", 1 },
  { "2021", 2 },
  { "3031", 2 },
  { "40414243", 4 },
  { "5051525354555657", 8 },
  { "606162636465666768696a6b6c6d6e6f", 16 },
};

// Level counts for number of leaves in [1, 8]
const size_t kLevelCounts[8] = {1, 2, 3, 3, 4, 4, 4, 4};

// Incremental roots from building the reference tree from inputs leaf-by-leaf.
// Generated from ReferenceMerkleTreeHash.
const TestVector kSHA256Roots[8] = {
  { "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", 32 },
  { "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", 32 },
  { "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", 32 },
  { "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32 },
  { "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4", 32 },
  { "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef", 32 },
  { "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c", 32 },
  { "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328", 32 }
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
      assert(tree1.RootAtSnapshot(j + 1) == bstring());
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
      { "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        32 },
      { "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        32 },
      { "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        32 }
    }},
  { 6, 8, 3, {
      { "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        32 },
      { "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        32 },
      { "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        32 }
    }},
  { 3, 3, 1, {
      { "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        32 },
      { "", 0 }, { "", 0 }
    }},
  { 2, 5, 3, {
      { "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        32 },
      { "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        32 },
      { "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
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
    std::vector<bstring> path = tree1.PathToRootAtSnapshot(
        kSHA256Paths[i].leaf, kSHA256Paths[i].snapshot);
    std::vector<bstring> kat_path;
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
      { "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        32 },
      { "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        32 },
      { "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        32 }
    }},
  { 6, 8, 3, {
      { "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
        32 },
      { "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        32 },
      { "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        32 }
    }},
  { 2, 5, 2, {
      { "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        32 },
      { "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
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
    std::vector<bstring> proof = tree1.SnapshotConsistency(
        kSHA256Proofs[i].snapshot1, kSHA256Proofs[i].snapshot2);
    std::vector<bstring> kat_proof;
    for (int j = 0; j < kSHA256Proofs[i].proof_length; ++j)
      kat_proof.push_back(S(kSHA256Proofs[i].proof[j]));
    assert(proof == kat_proof);
  }
}

////////////////////////////////////////////////////////////////////////////////
//                          VERIFICATION TESTS                                //
////////////////////////////////////////////////////////////////////////////////

void VerifierCheck(int leaf, int tree_size,
                   const std::vector<bstring> &path,
                   const bstring &root,
                   const bstring &data, MerkleVerifier *verifier) {
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
  const unsigned char wrong_leaf[] = "WrongLeaf";
  assert(!verifier->VerifyPath(leaf, tree_size, path, root, bstring(wrong_leaf, 9)));

  // Wrong root.
  assert(!verifier->VerifyPath(leaf, tree_size, path,
                               S(kSHA256EmptyTreeHash), data));

  // Wrong paths.
  std::vector<bstring> wrong_path;

  // Modify a single element on the path.
  for (size_t j = 0; j < path.size(); ++j) {
    wrong_path = path;
    wrong_path[j] = S(kSHA256EmptyTreeHash);
    assert(!verifier->VerifyPath(leaf, tree_size, wrong_path, root, data));
  }

  // Add garbage at the end of the path.
  wrong_path = path;
  wrong_path.push_back(bstring());
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
  wrong_path.push_back(bstring());
  wrong_path.insert(wrong_path.end(), path.begin(), path.end());
  assert(!verifier->VerifyPath(leaf, tree_size, wrong_path, root, data));

  wrong_path[0] = root;
  assert(!verifier->VerifyPath(leaf, tree_size, wrong_path, root, data));
}

void VerifierConsistencyCheck(int snapshot1, int snapshot2,
                              const bstring &root1,
                              const bstring &root2,
                              const std::vector<bstring> &proof,
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
  const unsigned char wrong_root[] = "WrongRoot";
  const bstring bwrong_root(wrong_root, 9);
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root1, bwrong_root,
                                      proof));
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, bwrong_root, root2,
                                      proof));
  // Swap roots.
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root2, root1,
                                      proof));

  // Wrong proofs.
  std::vector<bstring> wrong_proof;
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
  wrong_proof.push_back(bstring());
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
  wrong_proof.push_back(bstring());
  wrong_proof.insert(wrong_proof.end(), proof.begin(), proof.end());
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root1, root2,
                                      wrong_proof));

  wrong_proof[0] = proof[0];
  assert(!verifier->VerifyConsistency(snapshot1, snapshot2, root1, root2,
                                      wrong_proof));
}

void VerifierTest() {
  MerkleVerifier verifier(new Sha256Hasher());
  std::vector<bstring> path;
  // Various invalid paths.
  assert(!verifier.VerifyPath(0, 0, path, bstring(), bstring()));
  assert(!verifier.VerifyPath(0, 1, path, bstring(), bstring()));
  assert(!verifier.VerifyPath(1, 0, path, bstring(), bstring()));
  assert(!verifier.VerifyPath(2, 1, path, bstring(), bstring()));

  assert(!verifier.VerifyPath(0, 0, path, S(kSHA256EmptyTreeHash), bstring()));
  assert(!verifier.VerifyPath(0, 1, path, S(kSHA256EmptyTreeHash), bstring()));
  assert(!verifier.VerifyPath(1, 0, path, S(kSHA256EmptyTreeHash), bstring()));
  assert(!verifier.VerifyPath(2, 1, path, S(kSHA256EmptyTreeHash), bstring()));

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
  bstring data[128];
  for (int i = 0; i < 128; ++i)
    data[i] = bstring(1, static_cast<char>(i));
  TreeHasher treehasher(new Sha256Hasher());

  bstring root;
  // Repeat test for each tree size in 1...128.
  for (int tree_size = 1; tree_size <= 128; ++tree_size) {
    // Repeat for each leaf in range.
    for (int leaf = 1; leaf <= tree_size; ++leaf) {
      path = ReferenceMerklePath(data, tree_size, leaf, &treehasher);
      root = ReferenceMerkleTreeHash(data, tree_size, &treehasher);
      VerifierCheck(leaf, tree_size, path, root, data[leaf - 1], &verifier);
    }
  }

  std::vector<bstring> proof;
  bstring root1, root2;
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
