#include "../include/types.h"
#include "SerialHasher.h"
#include "TreeHasher.h"


const bstring TreeHasher::kLeafPrefix(1, '\x00');
const bstring TreeHasher::kNodePrefix(1, '\x01');

TreeHasher::TreeHasher(SerialHasher *hasher) : hasher_(hasher) {}

TreeHasher::~TreeHasher() {
  delete hasher_;
}

bstring TreeHasher::HashEmpty() {
  if (emptyhash_.empty()) {
    // First call to HashEmpty(); since the hash of an empty string is constant,
    // set it up once and for all.
    hasher_->Reset();
    emptyhash_ = hasher_->Final();
  }
  return emptyhash_;
}

bstring TreeHasher::HashLeaf(const bstring &data) {
  hasher_->Reset();
  hasher_->Update(kLeafPrefix);
  hasher_->Update(data);
  return hasher_->Final();
}

bstring TreeHasher::HashChildren(const bstring &left_child,
                                 const bstring &right_child) {
  hasher_->Reset();
  hasher_->Update(kNodePrefix);
  hasher_->Update(left_child);
  hasher_->Update(right_child);
  return hasher_->Final();
}
