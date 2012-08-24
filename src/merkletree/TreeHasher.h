#ifndef TREEHASHER_H
#define TREEHASHER_H

#include <stddef.h>

#include "serial_hasher.h"
#include "types.h"

class TreeHasher {
 public:
  // Takes ownership of the SerialHasher.
  TreeHasher(SerialHasher *hasher);
  ~TreeHasher();

  size_t DigestSize() const { return hasher_->DigestSize(); }

  bstring HashEmpty();

  bstring HashLeaf(const bstring &data);

  // Accepts arbitrary strings as children. When hashing
  // digests, it is the responsibility of the caller to
  // ensure the inputs are of correct size.
  bstring HashChildren(const bstring &left_child, const bstring &right_child);

 private:
  SerialHasher *hasher_;
  static const bstring kLeafPrefix;
  static const bstring kNodePrefix;
  // The dummy hash of an empty tree.
  bstring emptyhash_;
};
#endif
