#include <stddef.h>
#include <string>
#include <vector>

#include "MerkleVerifier.h"

class SerialHasher;

MerkleVerifier::MerkleVerifier(SerialHasher *hasher) : treehasher_(hasher) {
}

MerkleVerifier::~MerkleVerifier() {}

static inline size_t Parent(size_t leaf) {
  return leaf >> 1;
}

static inline bool IsRightChild(size_t leaf) {
  return leaf & 1;
}

bool MerkleVerifier::VerifyPath(size_t leaf, size_t tree_size,
                                const std::vector<std::string> &path,
                                const std::string &data) {
  if (leaf > tree_size || leaf == 0)
    // No valid path exists.
    return false;

  size_t node = leaf - 1;
  size_t last_node = tree_size  - 1;

  std::string node_hash = treehasher_.HashLeaf(data);
  if (path.empty())
    return false;
  std::vector<std::string>::const_iterator it = path.begin();

  while (last_node) {
    if (IsRightChild(node))
      node_hash = treehasher_.HashChildren(*it++, node_hash);
    else if (node < last_node)
      node_hash = treehasher_.HashChildren(node_hash, *it++);
    // Else the sibling does not exist and the parent is a dummy copy.
    // Do nothing.

    if (it == path.end())
      // We've reached the end but we're not done yet.
      return false;
    node = Parent(node);
    last_node = Parent(last_node);
  }

  // Check that the result equals the root and that we've reached the end.
  if (node_hash != *it || ++it != path.end())
    return false;
  return true;
}
