#include "merkletree/serial_hasher.h"
#include "merkletree/tree_hasher.h"

using std::string;

const string TreeHasher::kLeafPrefix(1, '\x00');
const string TreeHasher::kNodePrefix(1, '\x01');

TreeHasher::TreeHasher(SerialHasher *hasher) : hasher_(hasher) {}

TreeHasher::~TreeHasher() {
  delete hasher_;
}

string TreeHasher::HashEmpty() {
  if (emptyhash_.empty()) {
    // First call to HashEmpty(); since the hash of an empty string is constant,
    // set it up once and for all.
    hasher_->Reset();
    emptyhash_ = hasher_->Final();
  }
  return emptyhash_;
}

string TreeHasher::HashLeaf(const string &data) {
  hasher_->Reset();
  hasher_->Update(kLeafPrefix);
  hasher_->Update(data);
  return hasher_->Final();
}

string TreeHasher::HashChildren(const string &left_child,
                                 const string &right_child) {
  hasher_->Reset();
  hasher_->Update(kNodePrefix);
  hasher_->Update(left_child);
  hasher_->Update(right_child);
  return hasher_->Final();
}
