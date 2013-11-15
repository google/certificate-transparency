#include <glog/logging.h>
#include <stddef.h>
#include <string>
#include <vector>

#include "merkletree/compact_merkle_tree.h"
#include "merkletree/merkle_tree_math.h"

using std::string;

class SerialHasher;

CompactMerkleTree::CompactMerkleTree(SerialHasher *hasher)
    : ct::MerkleTreeInterface(),
      treehasher_(hasher),
      leaf_count_(0),
      leaves_processed_(0),
      level_count_(0) {
  root_ = treehasher_.HashEmpty();
}

CompactMerkleTree::~CompactMerkleTree() {}


size_t CompactMerkleTree::AddLeaf(const string &data) {
  return AddLeafHash(treehasher_.HashLeaf(data));
}

size_t CompactMerkleTree::AddLeafHash(const string &hash) {
  PushBack(0, hash);
  // Update level count: a k-level tree can hold 2^{k-1} leaves,
  // so increment level count every time we overflow a power of two.
  // Do not update the root; we evaluate the tree lazily.
  if (MerkleTreeMath::IsPowerOfTwoPlusOne(++leaf_count_))
    ++level_count_;
  return leaf_count_;
}

string CompactMerkleTree::CurrentRoot() {
  UpdateRoot();
  return root_;
}

void CompactMerkleTree::PushBack(size_t level, string node) {
  CHECK_EQ(node.size(), treehasher_.DigestSize());
  if (tree_.size() <= level) {
    // First node at a new level.
    tree_.push_back(node);
  } else if (tree_[level].empty()) {
    // Lone left sibling.
    tree_[level] = node;
  } else {
    // Left sibling waiting: hash together and propagate up.
    PushBack(level + 1, treehasher_.HashChildren(tree_[level], node));
    tree_[level].clear();
  }
}

void CompactMerkleTree::UpdateRoot() {
  if (leaves_processed_ == LeafCount())
    return;

  string right_sibling;

  for (size_t level = 0; level < tree_.size(); ++level) {
    if (!tree_[level].empty()) {
      // A lonely left sibling gets pulled up as a right sibling.
      if (right_sibling.empty())
        right_sibling = tree_[level];
      else
        right_sibling = treehasher_.HashChildren(tree_[level], right_sibling);
    }
  }

  root_ = right_sibling;
  leaves_processed_ = LeafCount();
}
