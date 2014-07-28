/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef CERT_TRANS_SERVER_LOGGED_BLOB_H_
#define CERT_TRANS_SERVER_LOGGED_BLOB_H_

#include <glog/logging.h>
#include <stdint.h>

#include "merkletree/serial_hasher.h"

class LoggedBlob {
 public:
  LoggedBlob() : sequence_set_(false) {}
  LoggedBlob(const std::string &blob) : blob_(blob), sequence_set_(false) {}

  std::string Hash() const {
    return Sha256Hasher::Sha256Digest(blob_);
  }

  void clear_sequence_number() {
    sequence_set_ = false;
  }

  void set_sequence_number(uint64_t sequence) {
    sequence_ = sequence;
    sequence_set_ = true;
  }

  bool has_sequence_number() const {
    return sequence_set_;
  }

  uint64_t sequence_number() const {
    CHECK(sequence_set_);
    return sequence_;
  }

  uint64_t timestamp() const {
    return 0;
  }

  bool SerializeForDatabase(std::string *dst) const {
    *dst = blob_;
    return true;
  }

  bool ParseFromDatabase(const std::string &src) {
    blob_ = src;
    return true;
  }

  bool SerializeForLeaf(std::string *dst) const {
    *dst = blob_;
    return true;
  }

  std::string DebugString() const {
    return "debug!";
  }

 private:
  std::string blob_;
  bool sequence_set_;
  uint64_t sequence_;
};

#endif  // CERT_TRANS_SERVER_LOGGED_BLOB_H_
