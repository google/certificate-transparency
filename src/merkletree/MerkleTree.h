#ifndef MERKLETREE_H
#define MERKLETREE_H
#include <string>
#include <vector>

#include "TreeHasher.h"

class SerialHasher;

// Class for manipulating Merkle Hash Trees
// TODO(ekasper): an equivalent "public" counterpart for verifying Merkle paths
// emitted by this class, using the same underlying TreeHasher.
class MerkleTree {
 public:
  // Takes ownership of the SerialHasher.
  MerkleTree(SerialHasher *hasher);
  ~MerkleTree();

  size_t NodeSize() const { return treehasher_. DigestSize(); };

  unsigned int LeafCount() const { return tree_.empty() ? 0 : tree_[0].size(); }

  // Number of levels. An empty tree has 0 levels, a tree with 1 leaf has
  // 1 level, a tree with 2 leaves has 2 levels, and a tree with n leaves has
  // ceil(log2(n)) + 1 levels.
  unsigned int LevelCount() const;

  // Add a new leaf to the hash tree. Stores the hash of the leaf data in the
  // tree structure, does not store the data itself.
  //
  // (We will evaluate the tree lazily, and not update the root here.)
  //
  // Returns the position of the leaf in the tree. Indexing starts at 1,
  // so position = number of leaves in the tree after this update.
  //
  // @param data Binary input blob
  unsigned int AddLeaf(const std::string& data);

  // Get the current root of the tree.
  // Update the root to reflect the current shape of the tree,
  // and return the tree digest.
  //
  // Returns the hash of an empty string if the tree has no leaves
  // (and hence, no root).
  std::string CurrentRoot();

  // Get the root of the tree for a previous snapshot,
  // where snapshot 0 is an empty tree, snapshot 1 is the tree with
  // 1 leaf, etc.
  //
  // Returns an empty string if the snapshot requested is in the future
  // (i.e., the tree is not large enough).
  //
  // @param snapshot point in time (= number of leaves at that point).
  std::string RootAtSnapShot(unsigned int snapshot);


  // Get the Merkle path from leaf to root.
  //
  // Returns a vector of node hashes, where the first element is the leaf hash
  // and the remaining nodes are ordered according to levels from leaf to root.
  // Returns an empty vector if the tree is not large enough.
  //
  // @param leaf the index of the leaf the path is for.
  std::vector<std::string> PathToCurrentRoot(unsigned int leaf);

  // Get the Merkle path from leaf to the root of a previous snapshot.
  //
  // Returns a vector of node hashes, where the first element is the leaf hash
  // and the remaining nodes are ordered according to levels from leaf to root.
  // Returns an empty vector if the snapshot requested is in the future
  // or the snapshot tree is not large enough.
  //
  // @param leaf the index of the leaf the path is for.
  // @param snapshot point in time (= number of leaves at that point)
  std::vector<std::string> PathToRootAtSnapshot(unsigned int leaf,
                                                unsigned int snapshot);

 private:
  // A container for nodes, organized according to levels and sorted
  // left-to-right in each level. tree_[0] is the leaf level, etc.
  std::vector< std::vector<std::string> > tree_;
  TreeHasher treehasher_;
  // Number of leaves propagated up to the root,
  // to keep track of lazy evaluation.
  unsigned int leaves_processed_;
};
#endif
