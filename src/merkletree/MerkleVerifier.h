#ifndef MERKLEVERIFIER_H
#define MERKLEVERIFIER_H

#include <stddef.h>
#include <vector>

#include "tree_hasher.h"
#include "types.h"

class SerialHasher;

// Class for verifying paths emitted by MerkleTrees.
// TODO: consistency proofs between snapshots.

class MerkleVerifier {
 public:
  // Takes ownership of the SerialHasher.
  MerkleVerifier(SerialHasher *hasher);
  ~MerkleVerifier();

  // Verify Merkle path. Return true iff the path is a valid proof for
  // the leaf in the tree, i.e., iff 0 < leaf <= tree_size and path
  // is a valid path from the leaf hash of data to the root.
  //
  // @param leaf index of the leaf.
  // @param tree_size number of leaves in the tree.
  // @param path a vector of node hashes ordered according to levels from leaf
  // to root. Does not include the leaf hash or the root.
  // @ param root The root hash
  // @ param data The leaf data
  bool VerifyPath(size_t leaf, size_t tree_size,
                  const std::vector<bstring> &path, const bstring &root,
                  const bstring &data);

  // Compute the root corresponding to a Merkle audit path.
  // Returns an empty string if the path is not valid.
  //
  // @param leaf index of the leaf.
  // @param tree_size number of leaves in the tree.
  // @param path a vector of node hashes ordered according to levels from leaf
  // to root. Does not include the leaf hash or the root.
  // @ param data The leaf data
  bstring RootFromPath(size_t leaf, size_t tree_size,
                       const std::vector<bstring> &path, const bstring &data);

  bool VerifyConsistency(size_t snapshot1, size_t snapshot2,
                         const bstring &root1, const bstring &root2,
                         const std::vector<bstring> &proof);
 private:
  TreeHasher treehasher_;
};

# endif
