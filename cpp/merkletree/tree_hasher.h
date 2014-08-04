#ifndef TREEHASHER_H
#define TREEHASHER_H

#include <stddef.h>

#include "base/macros.h"
#include "merkletree/serial_hasher.h"

class TreeHasher {
 public:
  // Takes ownership of the SerialHasher.
  TreeHasher(SerialHasher *hasher);
  ~TreeHasher();

  size_t DigestSize() const { return hasher_->DigestSize(); }

  std::string HashEmpty();

  std::string HashLeaf(const std::string &data) const;

  // Accepts arbitrary strings as children. When hashing
  // digests, it is the responsibility of the caller to
  // ensure the inputs are of correct size.
  std::string HashChildren(const std::string &left_child,
                           const std::string &right_child);

 private:
  SerialHasher *hasher_;
  static const std::string kLeafPrefix;
  static const std::string kNodePrefix;
  // The dummy hash of an empty tree.
  std::string emptyhash_;

  DISALLOW_COPY_AND_ASSIGN(TreeHasher);
};
#endif
