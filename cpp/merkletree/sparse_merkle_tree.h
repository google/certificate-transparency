#ifndef CERT_TRANS_MERKLETREE_SPARSE_MERKLE_TREE_H
#define CERT_TRANS_MERKLETREE_SPARSE_MERKLE_TREE_H

#include <glog/logging.h>
#include <stddef.h>
#include <array>
#include <string>
#include <unordered_map>
#include <vector>

#include "merkletree/merkle_tree_interface.h"
#include "merkletree/tree_hasher.h"
#include "util/bignum.h"

class SerialHasher;


// Calculates the set of "null" hashes:
// ...H(H(H("")||H(""))||H("")||(H(""))||...)...
//
// Visible out here because it's useful for testing too.
const std::vector<std::string>* GetNullHashes(const TreeHasher& hasher);


// Implementation of a Sparse Merkle Tree.
//
// The design is inspired by the tree described in
// http://www.links.org/files/RevocationTransparency.pdf), but with some
// tweaks, most notably:
//   1) Leaf values are hashed before being incorporated into the tree.
//   2) Similar to the way it works in the CT MerkleTree, hashes are domain
//      separated by prefixing the preimage with \x00 for leaves, and \x01 for
//      internal nodes.
//
//
// These mean that level 2 nodes are of the form:
//      H(\x01||H(\0x00||valueL)||H(\0x00||valueR))
// and so on.
//
// Nodes are addressed by a Path, which is a bit-string of the same length as
// the output of the hashing fuction used.  This string describes a path down
// from the root to a leaf, with the 0-bits indicating the path takes the
// left-hand child branch, and 1-bits the right. e.g:
//        Root
//        /  \
//      0/    \1
//      /      \
//     i0      i3
//   0/ \1   0/  \1
//   /   \   /    \
//  l0  l1  l2    l3
//
//  The paths to the 4 leaves would then be:
//  l0: "00"
//  l1: "01"
//  l2: "10"
//  l3: "11"
//
// To help with memory consumption, leaves inserted into the tree are stored
// at the first unused node along their path.  An example is given below:
//
// * Empty tree:
//      Root
//
// * Add "10" = "hi":
// Since the tree is empty, the first bit of the added path is sufficient to
// identify a unique prefix, so the leaf is stored as the "1" entry
// immediately below the root.
//              Root
//                |
//                |_______1
//                       p:"10"
//                       v:"hi"
//
// * Add "11" = "to":
// The first bit of the added path is not enough to provide a unique
// prefix so the leaf node currently occupying the "1" node immediately below
// the root must be pushed down a level, resulting in:
//              Root
//                |
//                |_______1
//                        |
//                        |
//                  0_____|_____1
//                  |           |
//                p:"10"      p:"11"
//                v:"hi"      v:"to"
//
// (In the case where paths are longer and multiple bits of the prefix collide,
// the existing node is repeated pushed down a level until a unique prefix is
// found.)
//
// * Add "00" = "aa":
// The first bit of the added path is unique, and so the resulting tree is:
//              Root
//                |
//        0_______|_______1
//        |               |
//      p:"00"            |
//      v:"aa"      0_____|_____1
//                  |           |
//                p:"10"      p:"11"
//                v:"hi"      v:"to"
//
// * Calculating the root hash
// Calculating the root of the tree is similar to a regular MerkleTree, but is
// optimised by cribbing the value of "missing" nodes from a simple cache. This
// removes the need to calculate the vast majority of nodes from scratch.
//
// TODO(alcutter): LOTS!
//
// This class is thread-compatible, but not thread-safe.
class SparseMerkleTree {
 public:
  static const int kDigestSizeBits = 256;

  // Represents a path into the SparseMerkleTree.
  // The MSB specifies the child of the root node of the tree, and so on until
  // the LSB of the BigNum specifies the leaf itself.
  //
  // i.e:
  // [M..............................L]
  //  ||                             |_____LSB of path, identifies leaf at
  //  lowest level in the tree
  //  ||___________________________________Identifies 2nd level child node
  //  |____________________________________Identifies 1st level child node
  //
  //  The reasoning behind this convention is that looked as a single
  //  kDigestSizeBits sized word, the value of the path is then the same as
  //  the index of the leaf node it identifies, this also has the advantage
  //  that the paths are lexographically sortable.
  typedef cert_trans::BigNum Path;

  struct PathHasher;

  // The constructor takes a pointer to some concrete hash function
  // instantiation of the SerialHasher abstract class.
  // Takes ownership of the hasher.
  explicit SparseMerkleTree(SerialHasher* hasher);

  // Length of a node (i.e., a hash), in bytes.
  virtual size_t NodeSize() const {
    return treehasher_.DigestSize();
  };

  // Return the leaf hash, but do not append the data to the tree.
  virtual std::string LeafHash(const std::string& data) const {
    return treehasher_.HashLeaf(data);
  }

  // Add a new leaf to the hash tree. Stores the hash of the leaf data in the
  // tree structure, does not store the data itself.
  //
  // @param data Binary input blob
  // @param path Binary path of node to set.
  virtual void SetLeaf(const Path& path, const std::string& data);

  // Get the current root of the tree.
  // Update the root to reflect the current shape of the tree,
  // and return the tree digest.
  //
  // Returns the hash of an empty string if the tree has no leaves
  // (and hence, no root).
  virtual std::string CurrentRoot();

  // Get the Merkle path from the leaf at |path| to the current root.
  //
  // Returns a vector of node hashes, ordered by levels from leaf to root.
  // The first element is the sibling of the leaf hash, and the last element
  // is one below the root.
  // Returns an empty vector if the tree is not large enough
  // or the leaf index is 0.
  //
  // @param path the path of the leaf whose inclusion proof to return.
  std::vector<std::string> InclusionProof(const Path& path) const;

  std::string Dump() const;

 private:
  typedef cert_trans::BigNum IndexType;

  struct TreeNode {
    TreeNode(const std::string& hash) : type_(INTERNAL), hash_(hash) {
    }

    TreeNode(const Path& path, const std::string& leaf_hash)
        : type_(LEAF), path_(path), hash_(leaf_hash) {
    }

    std::string DebugString() const;

    enum { INTERNAL, LEAF } type_;
    Path path_;
    std::string hash_;
  };

  std::string CalculateSubtreeHash(size_t depth, IndexType index);

  void DumpTree(std::ostream* os, size_t depth, IndexType index) const;

  // Get the |index|-th node at level |level|. Indexing starts at 0;
  // caller is responsible for ensuring tree is sufficiently up to date.
  std::string Node(size_t level, size_t index) const;

  // Maybe add a new tree level.
  void EnsureHaveLevel(size_t n);

  std::unique_ptr<SerialHasher> serial_hasher_;
  TreeHasher treehasher_;
  const std::vector<std::string>* const null_hashes_;
  // TODO(alcutter): investigate other structures
  std::vector<std::unordered_map<IndexType, TreeNode, PathHasher>> tree_;
  std::string root_hash_;
};


// Pretty print a Path
std::ostream& operator<<(std::ostream& out,
                         const SparseMerkleTree::Path& path);


// Creates a Path from the bits passed in.
inline SparseMerkleTree::Path PathFromBytes(const std::string& bytes) {
  CHECK_EQ(SparseMerkleTree::kDigestSizeBits / 8, bytes.size());
  SparseMerkleTree::Path path(0);
  for (const auto& b : bytes) {
    path <<= 8;
    path += static_cast<uint8_t>(b);
  }
  return path;
}


std::string BytesFromPath(const SparseMerkleTree::Path& path) {
  const size_t digest_num_bytes(SparseMerkleTree::kDigestSizeBits / 8);
  const size_t path_num_bytes(BN_num_bytes(path.bn()));
  CHECK_LE(path_num_bytes, digest_num_bytes);

  std::array<char, digest_num_bytes> buf;

  // The path's binary representation may not be digest_num_bytes long, so
  // we may need to start writing it at some offset from the start of the
  // array:
  const size_t offset(digest_num_bytes - path_num_bytes);

  // if so, set the bytes we won't write to zeros
  std::fill(buf.begin(), buf.begin() + offset, 0);

  // Then let BigNum do its thing:
  BN_bn2bin(path.bn(), reinterpret_cast<unsigned char*>(buf.data() + offset));

  return std::string(buf.begin(), buf.end());
}


// Extracts the |n|th most significant bit from |path|
inline int PathBit(const SparseMerkleTree::Path& path, size_t bit) {
  return path.bit(SparseMerkleTree::kDigestSizeBits - 1 - bit);
}


// Careful...
// This hasher only hashes the bottom 64 bits of |path|.
// This is probably sufficient for the intended use of bucketing Paths into an
// unordered_map, but is otherwise likely not what you're looking for.
struct SparseMerkleTree::PathHasher {
  size_t operator()(const SparseMerkleTree::Path& p) const {
    const uint64_t bottom64(BN_get_word(p.bn()));
    return std::hash<uint64_t>()(bottom64);
  }
};


#endif  // CERT_TRANS_MERKLETREE_SPARSE_MERKLE_TREE_H
