#include <string>

#include "SerialHasher.h"
#include "TreeHasher.h"


const std::string TreeHasher::kLeafPrefix("\x00", 1);
const std::string TreeHasher::kNodePrefix("\x01", 1);

TreeHasher::TreeHasher(SerialHasher *hasher) : hasher_(hasher) {}

TreeHasher::~TreeHasher() {
  delete hasher_;
}

std::string TreeHasher::HashEmpty() {
  if (emptyhash_.empty()) {
    // First call to HashEmpty(); since the hash of an empty string is constant,
    // set it up once and for all.
    hasher_->Reset();
    emptyhash_ = hasher_->Final();
  }
  return emptyhash_;
}

std::string TreeHasher::HashLeaf(const std::string &data) {
  hasher_->Reset();
  hasher_->Update(kLeafPrefix);
  hasher_->Update(data);
  return hasher_->Final();
}

std::string TreeHasher::HashChildren(const std::string &left_child,
                                     const std::string &right_child) {
  hasher_->Reset();
  hasher_->Update(kNodePrefix);
  hasher_->Update(left_child);
  hasher_->Update(right_child);
  return hasher_->Final();
}
