#include "cpp/merkletree/sparse_merkle_tree.h"

#include <stddef.h>
#include <algorithm>
#include <vector>

#include "merkletree/merkle_tree_math.h"
#include "util/util.h"

using std::make_pair;
using std::ostream;
using std::ostringstream;
using std::reverse;
using std::string;
using std::unique_ptr;
using std::unordered_map;
using std::vector;


const vector<string>* GetNullHashes(const TreeHasher& hasher) {
  static unique_ptr<const vector<string>> null_hashes;
  if (!null_hashes) {
    vector<string> r{hasher.HashLeaf("")};
    for (int i(1); i < hasher.DigestSize() * 8; ++i) {
      r.emplace_back(hasher.HashChildren(r.back(), r.back()));
    }
    reverse(r.begin(), r.end());
    null_hashes.reset(new vector<string>(std::move(r)));
  }
  return null_hashes.get();
}


SparseMerkleTree::SparseMerkleTree(SerialHasher* hasher)
    : serial_hasher_(CHECK_NOTNULL(hasher)->Create()),
      treehasher_(hasher),
      null_hashes_(GetNullHashes(treehasher_)) {
}


void SparseMerkleTree::EnsureHaveLevel(size_t level) {
  if (tree_.size() < (level + 1)) {
    tree_.resize(level + 1);
  }
}


void SparseMerkleTree::SetLeafByHash(const string& key, const string& data) {
  serial_hasher_->Reset();
  serial_hasher_->Update(key);
  return SetLeaf(PathFromBytes(serial_hasher_->Final()), data);
}


void SparseMerkleTree::SetLeaf(const Path& path, const string& data) {
  CHECK_EQ(treehasher_.DigestSize(), path.size());
  // Mark the tree dirty:
  root_hash_.clear();

  IndexType node_index(0);
  for (int depth(0); depth <= kDigestSizeBits; ++depth) {
    node_index += PathBit(path, depth);
    EnsureHaveLevel(depth);
    auto it(tree_[depth].find(node_index));
    if (it == tree_[depth].end()) {
      CHECK(tree_[depth]
                .emplace(make_pair(node_index, TreeNode(path, data)))
                .second);
      return;
    } else if (it->second.type_ == TreeNode::INTERNAL) {
      // Mark the internal node hash dirty
      it->second.hash_.reset();
    } else if (it->second.leaf_->path_ == path) {
      // replacement
      CHECK_EQ(TreeNode::LEAF, it->second.type_);
      it->second.leaf_->value_ = data;
      return;
    } else {
      // restructure: push the existing node down a level and replace this one
      // with an INTERNAL node
      CHECK_LT(depth, kDigestSizeBits);
      EnsureHaveLevel(depth + 1);
      IndexType child_index((node_index << 1) +
                            PathBit(it->second.leaf_->path_, depth + 1));
      CHECK(tree_[depth + 1]
                .emplace(make_pair(child_index, std::move(it->second)))
                .second);
      it->second.type_ = TreeNode::INTERNAL;
      it->second.leaf_.reset();
    }
    node_index <<= 1;
  }
  LOG(FATAL) << "Failed to set " << path << " to " << data;
}


void SparseMerkleTree::DumpTree(ostream* os, size_t depth,
                                IndexType index) const {
  if (tree_.size() <= depth) {
    return;
  }
  const string indent((depth + 1) * 2, '-');
  for (int side(0); side < 2; ++side) {
    auto child(tree_[depth].find(index + side));
    if (child != tree_[depth].end()) {
      *os << indent << side << ": " << child->second.DebugString() << "\n";
      DumpTree(os, depth + 1, (index + side) << 1);
    }
  }
}


string SparseMerkleTree::Dump() const {
  ostringstream ret;
  ret << "\nTree [Root: " << util::ToBase64(root_hash_) << "]:\n";
  if (!tree_.empty()) {
    DumpTree(&ret, 0, 0);
  }
  return ret.str();
}


string SparseMerkleTree::CalculateSubtreeHash(size_t depth, IndexType index) {
  if (tree_.size() <= depth) {
    return null_hashes_->at(depth);
  }

  auto it(tree_[depth].find(index));
  if (it != tree_[depth].end()) {
    switch (it->second.type_) {
      case TreeNode::INTERNAL: {
        if (it->second.hash_) {
          return *(it->second.hash_);
        }
        IndexType left_child_index(index << 1);
        const string left(CalculateSubtreeHash(depth + 1, left_child_index));
        const string right(
            CalculateSubtreeHash(depth + 1, left_child_index + 1));
        it->second.hash_.reset(
            new string(treehasher_.HashChildren(left, right)));
        return *(it->second.hash_);
      }

      case TreeNode::LEAF: {
        string ret(treehasher_.HashLeaf(it->second.leaf_->value_));
        for (int i(kDigestSizeBits - 1); i > depth; --i) {
          if (PathBit(it->second.leaf_->path_, i) == 0) {
            ret = treehasher_.HashChildren(ret, null_hashes_->at(i));
          } else {
            ret = treehasher_.HashChildren(null_hashes_->at(i), ret);
          }
        }
        // TODO(alcutter): maybe cache this?
        return ret;
      }
    }
    LOG(FATAL) << "Unknown node type " << it->second.type_ << " !";
  }

  return null_hashes_->at(depth);
}


string SparseMerkleTree::CurrentRoot() {
  if (root_hash_.empty()) {
    root_hash_ = treehasher_.HashChildren(CalculateSubtreeHash(0, 0),
                                          CalculateSubtreeHash(0, 1));
  }
  return root_hash_;
}


std::vector<string> SparseMerkleTree::InclusionProof(const Path& path) {
  // TODO(alcutter): implement
  LOG(FATAL) << "Not implemented.";
}


string SparseMerkleTree::TreeNode::DebugString() const {
  ostringstream os;
  os << "[TreeNode ";
  switch (type_) {
    case INTERNAL:
      os << "INTL hash: ";
      if (hash_) {
        os << util::ToBase64(*hash_);
      } else {
        os << "(unset)";
      }
      break;
    case LEAF:
      os << "LEAF leaf: ";
      os << leaf_->DebugString();
      break;
  }
  os << "]";
  return os.str();
}


string SparseMerkleTree::Leaf::DebugString() const {
  ostringstream os;
  os << "[Leaf path: " << path_ << " value: " << value_ << "]";
  return os.str();
}


ostream& operator<<(ostream& out, const SparseMerkleTree::Path& path) {
  for (size_t i(0); i < path.size(); ++i) {
    uint8_t t(path[i]);
    for (size_t b(8); b > 0; --b) {
      out << (t & 0x80 ? '1' : '0');
      t <<= 1;
    }
  }
  return out;
}
