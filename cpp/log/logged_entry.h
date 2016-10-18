#ifndef CERT_TRANS_LOG_LOGGED_ENTRY_H_
#define CERT_TRANS_LOG_LOGGED_ENTRY_H_

#include <glog/logging.h>

#include "client/async_log_client.h"
#include "merkletree/serial_hasher.h"
#include "proto/ct.pb.h"

namespace cert_trans {

class LoggedEntry : private ct::LoggedEntryPB {
 public:
  // Pull only what is used.
  using LoggedEntryPB::Clear;
  using LoggedEntryPB::DebugString;
  using LoggedEntryPB::ParseFromArray;
  using LoggedEntryPB::ParseFromString;
  using LoggedEntryPB::SerializeToString;
  using LoggedEntryPB::Swap;
  using LoggedEntryPB::clear_sequence_number;
  using LoggedEntryPB::contents;
  using LoggedEntryPB::has_sequence_number;
  using LoggedEntryPB::sequence_number;
  using LoggedEntryPB::merkle_leaf_hash;
  using LoggedEntryPB::set_merkle_leaf_hash;
  using LoggedEntryPB::set_sequence_number;
  using LoggedEntryPB::CopyFrom;
  void CopyFrom(const LoggedEntry& from) {
    LoggedEntryPB::CopyFrom(from);
  }

  std::string Hash() const;

  uint64_t timestamp() const {
    return sct().timestamp();
  }

  const ct::SignedCertificateTimestamp& sct() const {
    return contents().sct();
  }

  ct::SignedCertificateTimestamp* mutable_sct() {
    return mutable_contents()->mutable_sct();
  }

  const ct::LogEntry& entry() const {
    return contents().entry();
  }

  ct::LogEntry* mutable_entry() {
    return mutable_contents()->mutable_entry();
  }

  bool SerializeForDatabase(std::string* dst) const {
    return contents().SerializeToString(dst);
  }

  bool ParseFromDatabase(const std::string& src) {
    return mutable_contents()->ParseFromString(src);
  }

  bool SerializeForLeaf(std::string* dst) const;
  bool SerializeExtraData(std::string* dst) const;

  // Note that this method will not fully populate the SCT.
  bool CopyFromClientLogEntry(const AsyncLogClient::Entry& entry);

  // FIXME(benl): unify with TestSigner?
  void RandomForTest();
};


inline bool operator==(const LoggedEntry& lhs, const LoggedEntry& rhs) {
  // TODO(alcutter): Do this properly
  std::string l_str, r_str;
  CHECK(lhs.SerializeToString(&l_str));
  CHECK(rhs.SerializeToString(&r_str));
  return l_str == r_str;
}


inline bool operator==(const ct::LogEntry& lhs, const ct::LogEntry& rhs) {
  // TODO(alcutter): Do this properly
  std::string l_str, r_str;
  CHECK(lhs.SerializeToString(&l_str));
  CHECK(rhs.SerializeToString(&r_str));
  return l_str == r_str;
}


inline bool operator==(const ct::SignedCertificateTimestamp& lhs,
                       const ct::SignedCertificateTimestamp& rhs) {
  // TODO(alcutter): Do this properly
  std::string l_str, r_str;
  CHECK(lhs.SerializeToString(&l_str));
  CHECK(rhs.SerializeToString(&r_str));
  return l_str == r_str;
}


}  // namespace cert_trans

#endif  // CERT_TRANS_LOG_LOGGED_ENTRY_H_
