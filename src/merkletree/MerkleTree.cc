#include <assert.h>
#include <stddef.h>
#include <string>
#include <vector>

#include "MerkleTree.h"

class SerialHasher;

MerkleTree::MerkleTree(SerialHasher *hasher) : treehasher_(hasher),
                                               leaves_processed_(0),
                                               level_count_(0) {
}

MerkleTree::~MerkleTree() {}

static inline size_t Parent(size_t leaf) {
  return leaf >> 1;
}

static inline bool IsRightChild(size_t leaf) {
  return leaf & 1;
}

static inline size_t Sibling(size_t leaf) {
  return (leaf & 1) ? (leaf - 1) : (leaf + 1);
}

size_t MerkleTree::AddLeaf(const std::string &data) {
  if (tree_.empty()) {
    tree_.push_back(std::vector<std::string>(0));
    // The first leaf hash is also the first root.
    leaves_processed_ = 1;
  }
  tree_[0].push_back(treehasher_.HashLeaf(data));
  size_t leaf_count = LeafCount();
  // Update level count. Do not update the root; we evaluate the tree lazily.
  if (leaf_count < 2 || !((leaf_count - 1) & (leaf_count - 2)))
    ++level_count_;
  // Return the current leaf count.
  return leaf_count;
}

std::string MerkleTree::CurrentRoot() {
  return RootAtSnapshot(LeafCount());
}

std::string MerkleTree::RootAtSnapshot(size_t snapshot) {
  if (snapshot == 0)
    return treehasher_.HashEmpty();
  size_t leaf_count = LeafCount();
  if (snapshot > leaf_count)
    return "";
  if (snapshot >= leaves_processed_)
    return UpdateToSnapshot(snapshot);
  // snapshot < leaves_processed_: recompute the snapshot root.
  return RecomputePastSnapshot(snapshot, 0, NULL);
}

std::vector<std::string> MerkleTree::PathToCurrentRoot(size_t leaf) {
  return PathToRootAtSnapshot(leaf, LeafCount());
}

std::vector<std::string>
MerkleTree::PathToRootAtSnapshot(size_t leaf, size_t snapshot) {
  std::vector<std::string> path;
  size_t leaf_count = LeafCount();
  if (leaf > snapshot || snapshot > leaf_count || leaf == 0)
    return path;

  std::string root;
  if (snapshot > leaves_processed_)
    // Bring the tree sufficiently up to date.
    root = UpdateToSnapshot(snapshot);

  size_t level = 0;
  // Position of the current node on the path at the current level.
  size_t node = leaf - 1;
  // Index of the last node at the current level for this snapshot view.
  size_t last_node = snapshot - 1;

  // Move up, recording the sibling of the current node at each level.
  while (last_node) {
    size_t sibling = Sibling(node);
    if (sibling < last_node)
      // The sibling is not the last node of the level in the snapshot
      // tree, so its value is correct in the tree.
      path.push_back(tree_[level][sibling]);
    else if (sibling == last_node) {
      // The sibling is the last node of the level in the snapshot tree,
      // so we get its value for the snapshot. Get the root in the same pass.
      std::string recompute_node;
      root = RecomputePastSnapshot(snapshot, level, &recompute_node);
      path.push_back(recompute_node);
    }
    // Else sibling > last_node so the sibling does not exist. Do nothing.
    // Continue moving up in the tree, ignoring dummy copies.

    node = Parent(node);
    last_node = Parent(last_node);
    ++level;
  };

  // Finally, attach the root, recomputing if necessary.
  if (root.empty())
    root = RecomputePastSnapshot(snapshot, 0, NULL);
  path.push_back(root);
  return path;
}

std::string MerkleTree::UpdateToSnapshot(size_t snapshot) {
  if (snapshot == 0)
    return treehasher_.HashEmpty();
  if (snapshot == leaves_processed_)
    return tree_.back()[0];
  assert(snapshot <= LeafCount());
  assert(snapshot > leaves_processed_);

  // Update tree, moving up level-by-level.
  size_t level = 0;
  // Index of the first node to be processed at the current level.
  size_t first_node = leaves_processed_;
  // Index of the last node.
  size_t last_node = snapshot - 1;

  // Process level-by-level until we converge to a single node.
  // (first_node, last_node) = (0, 0) means we have reached the root level.
  while (last_node) {
    if (tree_.size() <= level + 1)
      tree_.push_back(std::vector<std::string>(0));
    // The leftmost parent at level 'level+1' may already exist,
    // so we need to update it. Nuke the old parent.
    else if (tree_[level + 1].size() == Parent(first_node) + 1)
      tree_[level + 1].pop_back();
    assert(tree_[level + 1].size() == Parent(first_node));

    // Compute the parents of new nodes at the current level.
    // Start with a left sibling and parse an even number of nodes.
    for (size_t j = first_node & ~1; j < last_node; j += 2) {
      tree_[level + 1].push_back(treehasher_.HashChildren(
          tree_[level][j], tree_[level][j + 1]));
    }
    // If the last node at the current level is a left sibling,
    // dummy-propagate it one level up.
    if (!IsRightChild(last_node))
      tree_[level + 1].push_back(tree_[level][last_node]);

    first_node = Parent(first_node);
    last_node = Parent(last_node);
    ++level;
  };

  leaves_processed_ = snapshot;
  assert(tree_.back().size() == 1);
  return tree_.back()[0];
}

std::string MerkleTree::RecomputePastSnapshot(size_t snapshot,
                                              size_t node_level,
                                              std::string *node) {
  size_t level = 0;
  // Index of the rightmost node at the current level for this snapshot.
  size_t last_node = snapshot - 1;

  if (snapshot == leaves_processed_) {
    // Nothing to recompute.
    if (node && tree_.size() > node_level) {
      if (node_level > 0)
        node->assign(tree_[node_level].back());
      else
        // Leaf level: grab the last processed leaf.
        node->assign(tree_[node_level][last_node]);
    }
    return tree_.back()[0];
  }

  assert(snapshot < leaves_processed_);

  // Recompute nodes on the path of the last leaf.
  while (IsRightChild(last_node)) {
    if (node && node_level == level)
      node->assign(tree_[level][last_node]);
    // Left sibling and parent exist in the snapshot, and are equal to
    // those in the tree; no need to rehash, move one level up.
    last_node = Parent(last_node);
    ++level;
  }

  // Now last_node is the index of a left sibling with no right sibling.
  // Record the node.
  std::string subtree_root = tree_[level][last_node];

  if (node && node_level == level)
    node->assign(subtree_root);

  while (last_node) {
    if (IsRightChild(last_node))
      // Recompute the parent of tree_[level][last_node].
      subtree_root = treehasher_.HashChildren(
          tree_[level][last_node - 1], subtree_root);
    // Else the parent is a dummy copy of the current node; do nothing.

    last_node = Parent(last_node);
    ++level;
    if (node && node_level == level)
      node->assign(subtree_root);
  }

  return subtree_root;
}
