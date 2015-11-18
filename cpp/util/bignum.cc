#include "util/bignum.h"

namespace cert_trans {


BigNum::BigNum() {
  BN_init(&bn_);
}


BigNum::BigNum(int64_t w) : BigNum() {
  assert(BN_set_word(&bn_, w) == 1);
}


BigNum::BigNum(const BigNum& other) : BigNum() {
  if (&other.bn_ != &bn_) {
    assert(BN_copy(&bn_, &other.bn_) != nullptr);
  }
}


BigNum::~BigNum() {
  BN_free(&bn_);
}


void BigNum::clear() {
  CHECK_EQ(1, BN_set_word(&bn_, 0));
}


}  // namespace cert_trans
