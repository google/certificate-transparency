#ifndef CERT_TRANS_MERKLETREE_TREE_HASHER_H_
#define CERT_TRANS_MERKLETREE_TREE_HASHER_H_

#include <stddef.h>
#include <memory>
#include <mutex>
#include <string>

#include "merkletree/serial_hasher.h"

class TreeHasher {
 public:
  TreeHasher(std::unique_ptr<SerialHasher> hasher);
  TreeHasher(const TreeHasher&) = delete;
  TreeHasher& operator=(const TreeHasher&) = delete;

  size_t DigestSize() const {
    return hasher_->DigestSize();
  }

  const std::string& HashEmpty() const {
    return empty_hash_;
  }

  std::string HashLeaf(const std::string& data) const;

  // Accepts arbitrary strings as children. When hashing digests, it
  // is the responsibility of the caller to ensure the inputs are of
  // correct size.
  std::string HashChildren(const std::string& left_child,
                           const std::string& right_child) const;

 private:
  mutable std::mutex lock_;
  const std::unique_ptr<SerialHasher> hasher_;
  // The pre-computed hash of an empty tree.
  const std::string empty_hash_;
};

#endif  // CERT_TRANS_MERKLETREE_TREE_HASHER_H_
