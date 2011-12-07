#ifndef MERKLETREE_H
#define MERKLETREE_H
#include <string>
#include <vector>

#include "TreeHasher.h"

using std::string;
using std::vector;

// Class for manipulating Merkle Hash Trees
// TODO(ekasper): an equivalent "public" counterpart for verifying Merkle paths
// emitted by this class, using the same underlying TreeHasher.
class MerkleTree {
 public:
  MerkleTree(TreeHasher::HashAlgorithm alg);
  ~MerkleTree();

  typedef enum {
    OK,
    TREE_EMPTY
    // More stuff
  } TreeResult;

  TreeHasher::HashAlgorithm HashAlgorithm() const {
    return treehasher_.HashAlgorithm();
  }

  size_t NodeSize() const { return treehasher_.DigestSize(); };

  unsigned int LeafCount() const { return tree_.empty() ? 0 : tree_[0].size(); }

  // ceil(log2(leafcount))
  unsigned int LevelCount() const;

  // Add a new leaf to the hash tree. Stores the hash of the leaf data in the
  // tree structure, does not store the data itself.
  //
  // (We will evaluate the tree lazily, and not update the root here, methinks.)
  //
  // Returns the position of the leaf in the tree
  // (= number of leaves in the tree after this update).
  //
  // @param data Binary input blob
  unsigned int AddLeaf(const string& data);

  // Get the current root of the tree.
  // Update the root to reflect the current shape of the tree,
  // and return the root digest.
  //
  // Returns OK or TREE_EMPTY if the tree contains no leaves
  // (or simply an empty string in that case?)
  //
  // @param root Binary output blob.
  TreeResult RootHash(string *root);

  // Get the root of the tree for a previous snapshot.
  //
  // Returns OK or an error if the snapshot requested is in the future.
  //
  // @param snapshot point in time (= number of leaves at that point)
  // @param root Binary output blob.
  TreeResult RootHash(unsigned int snapshot, string *root);


  // Get the Merkle path from leaf to root.
  //
  // Returns OK or an error if the tree is not large enough.
  //
  // @param leaf the index of the leaf the path is for.
  // @param leaf_count current leafcount
  // @param leaf_hash Binary output blob for the leaf hash
  // @param path Binary blobs of the remaining nodes from leaf to root
  TreeResult PathToRoot(unsigned int leaf, unsigned int *leaf_count,
                        string *leaf_hash, vector<string> *path);

  // Get the Merkle path from leaf to the root of a previous snapshot.
  //
  // Returns OK or an error if the snapshot requested is in the future
  // or the snapshot tree is not large enough.
  //
  // @param leaf the index of the leaf the path is for.
  // @param snapshot point in time (= number of leaves at that point)
  // @param leaf_hash Binary output blob for the leaf hash
  // @param path Binary blobs of the remaining nodes from leaf to root
  TreeResult PathToRoot(unsigned int leaf, unsigned int snapshot,
                        string *leaf_hash, vector<string> *path);

 private:
  typedef struct {
    // A binary blob of the hash digest.
    string digest;
    // Maybe some other internal stuff? E.g. record if the node is a dummy,
    // in case we end up having any.
  } Node;

  // A container for Nodes, organized according to levels and sorted
  // left-to-right.
  // tree_[0] is the leaf level, etc.
  vector< vector<Node> > tree_;
  TreeHasher treehasher_;
  // Index of the last leaf that has been propagated up to the root,
  // to keep track of lazy evaluation.
  int last_processed_;
};
#endif
