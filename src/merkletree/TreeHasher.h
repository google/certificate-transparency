#ifndef TREEHASHER_H
#define TREEHASHER_H
#include <string>

using std::string;

#include "SerialHasher.h"

class TreeHasher {
 public:
  typedef enum {
    SHA256
    // etc
  } HashAlgorithm;

  // Instantiates a Hasher of the desired subclass.
  TreeHasher(HashAlgorithm alg);
  ~TreeHasher();

  HashAlgorithm HashAlgorithm() const { return alg_; }

  size_t DigestSize() const { return hasher_->DigestSize(); }

  void HashLeaf(const string &data, string *digest);

  void HashChildren(const string &left_child,
                    const string &right_child, string *digest);

 private:
  SerialHasher *hasher_;
  HashAlgorithm alg_;
};
#endif
