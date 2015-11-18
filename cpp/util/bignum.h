#ifndef CERT_TRANS_UTIL_BIGNUM_H_
#define CERT_TRANS_UTIL_BIGNUM_H_

#include <glog/logging.h>
#include <openssl/bn.h>
#include <cassert>

namespace cert_trans {


class BigNum {
 public:
  BigNum();
  explicit BigNum(int64_t w);
  BigNum(const BigNum& other);
  ~BigNum();

  const BIGNUM* bn() const;
  BIGNUM* bn();

  int num_bits() const;

  int bit(size_t n) const;

  void clear();

  BigNum operator+(const BigNum& n) const;
  BigNum operator+(int64_t n) const;

  BigNum& operator-=(const BigNum& n);
  BigNum& operator-=(int64_t n);
  BigNum& operator+=(const BigNum& n);
  BigNum& operator+=(int64_t n);
  BigNum& operator<<=(int n);
  BigNum& operator>>=(int n);

  int compare(const BigNum& rhs) const;

  bool operator==(const BigNum& rhs) const;

  bool operator<(const BigNum& rhs) const;

 private:
  BIGNUM bn_;
};


inline const BIGNUM* BigNum::bn() const {
  return &bn_;
}


inline BIGNUM* BigNum::bn() {
  return &bn_;
}


inline int BigNum::num_bits() const {
  return BN_num_bits(&bn_);
}


inline int BigNum::bit(size_t n) const {
  if (n >= num_bits()) {
    return false;
  }
  return BN_is_bit_set(&bn_, n);
}


inline BigNum BigNum::operator+(const BigNum& n) const {
  BigNum result(*this);
  result += n;
  return result;
}


inline BigNum BigNum::operator+(int64_t n) const {
  BigNum result(*this);
  result += n;
  return result;
}


inline BigNum& BigNum::operator-=(const BigNum& n) {
  assert(BN_sub(&bn_, &bn_, &n.bn_) == 1);
  return *this;
}


inline BigNum& BigNum::operator-=(int64_t n) {
  assert(BN_sub_word(&bn_, n) == 1);
  return *this;
}


inline BigNum& BigNum::operator+=(const BigNum& n) {
  assert(BN_add(&bn_, &bn_, &n.bn_) == 1);
  return *this;
}


inline BigNum& BigNum::operator+=(int64_t n) {
  assert(BN_add_word(&bn_, n) == 1);
  return *this;
}


inline BigNum& BigNum::operator<<=(int n) {
  assert(BN_lshift(&bn_, &bn_, n) == 1);
  return *this;
}


inline BigNum& BigNum::operator>>=(int n) {
  assert(BN_rshift(&bn_, &bn_, n) == 1);
  return *this;
}


inline int BigNum::compare(const BigNum& rhs) const {
  return BN_cmp(&bn_, &rhs.bn_);
}


inline bool BigNum::operator==(const BigNum& rhs) const {
  return compare(rhs) == 0;
}


inline bool BigNum::operator<(const BigNum& rhs) const {
  return compare(rhs) < 0;
}


inline BigNum operator<<(const BigNum& a, int n) {
  BigNum r(a);
  r <<= n;
  return r;
}


inline BigNum operator>>(const BigNum& a, int n) {
  BigNum r(a);
  r >>= n;
  return r;
}



namespace internal {


inline const BigNum& AsBigNum(const BigNum& n) {
  return n;
}


inline BigNum AsBigNum(int64_t n) {
  return BigNum(n);
}


}  // namespace internal


template <typename T>
inline bool operator==(const T& a, const BigNum& b) {
  return b.compare(internal::AsBigNum(a)) == 0;
}


template <typename T>
inline bool operator<(const T& a, const BigNum& b) {
  return b.compare(internal::AsBigNum(a)) >= 0;
}


template <typename T>
inline bool operator>(const T& a, const BigNum& b) {
  return b.compare(internal::AsBigNum(a)) <= 0;
}


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_BIGNUM_H_
