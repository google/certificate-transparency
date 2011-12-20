#ifndef MERKLEVERIFIER_H
#define MERKLEVERIFIER_H
#include <stddef.h>
#include <string>
#include <vector>

#include "TreeHasher.h"

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
  // to root. Does not include the leaf hash.
  bool VerifyPath(size_t leaf, size_t tree_size,
                  const std::vector<std::string> &path,
                  const std::string &data);

 private:
  TreeHasher treehasher_;
};

# endif
