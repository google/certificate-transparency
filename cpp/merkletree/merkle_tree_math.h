#ifndef CERT_TRANS_MERKLETREE_MERKLE_TREE_MATH_H_
#define CERT_TRANS_MERKLETREE_MERKLE_TREE_MATH_H_

#include <stddef.h>

class MerkleTreeMath {
 public:
  static bool IsPowerOfTwoPlusOne(size_t leaf_count);

  // Index of the parent node in the parent level of the tree.
  static size_t Parent(size_t leaf);

  // True if the node is a right child; false if it is the left (or only)
  // child.
  static bool IsRightChild(size_t leaf);

  // Index of the node's (left or right) sibling in the same level.
  static size_t Sibling(size_t leaf);

 private:
  MerkleTreeMath();
};

#endif  // CERT_TRANS_MERKLETREE_MERKLE_TREE_MATH_H_
