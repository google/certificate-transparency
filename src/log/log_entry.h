#ifndef LOG_ENTRY_H
#define LOG_ENTRY_H

#include <assert.h>
#include <vector>

#include "../include/types.h"
#include "../util/util.h"

#include "cert.h"

class LogEntry {
 public:
  // Two bytes when serialized.
  enum LogEntryType {
    X509_CHAIN_ENTRY = 0,
    PROTOCERT_CHAIN_ENTRY = 1,
    TEST_ENTRY = 65535,
  };

  // A factory method: logentry type is read from the record.
  // Returns NULL if the record does not deserialize.
  static LogEntry *Deserialize(const bstring &record);

  virtual ~LogEntry() {}

  virtual LogEntryType Type() const = 0;

  // Returns the serialized signed part of the entry.
  // We always include the entry type in the signed part.
  // Signed part cannot be empty.
  // struct {
  //  LogEntryType type;
  //  bstring signed_part;
  // } signed_part.
  bool SerializeSigned(bstring *signed_part) const {
    assert(signed_part != NULL);

    bstring serialized;
    if (!SerializeSignedImpl(&serialized) || serialized.empty())
      return false;
    bstring result = util::SerializeUint(Type(), 2);
    result.append(serialized);
    signed_part->assign(result);
    return true;
  }

  // struct {
  //  LogEntryType type;
  //  bstring entry;
  // } LogEntry;
  bool Serialize(bstring *record) const {
    assert(record != NULL);
    bstring entry;

    if (!SerializeImpl(&entry) || entry.empty())
      return false;

    bstring result = util::SerializeUint(Type(), 2);
    result.append(entry);
    record->assign(result);
    return true;
  }

 protected:
  virtual bool SerializeImpl(bstring *result) const = 0;
  // By default, everything is signed.
  virtual bool SerializeSignedImpl(bstring *result) const {
    return SerializeImpl(result);
  }
  virtual bool DeserializeImpl(const bstring &record) = 0;
};

// For testing.
class TestEntry : public LogEntry {
 public:
  TestEntry() {}
  TestEntry(const bstring &entry) : entry_(entry) {}

  ~TestEntry() {}

  LogEntryType Type() const { return LogEntry::TEST_ENTRY; }

 protected:
  bool SerializeImpl(bstring *result) const {
    assert(result != NULL);
    result->assign(entry_);
    return true;
  }

  bool DeserializeImpl(const bstring &record) {
    entry_ = record;
    return true;
  }

 private:
  bstring entry_;
};

class X509ChainEntry : public LogEntry {
 public:
  X509ChainEntry() {}
  X509ChainEntry(const CertChain &chain);

  ~X509ChainEntry() {}

  LogEntryType Type() const { return LogEntry::X509_CHAIN_ENTRY; }

 protected:
  // opaque ASN.1Cert <1..2^24-1>
  // struct {
  //    ASN.1Cert certificate_chain<1..2^24-1>;
  // } X509ChainEntry;
  bool SerializeImpl(bstring *result) const;
  bool DeserializeImpl(const bstring &record);
 private:
  std::vector<bstring> certificate_chain_;
};

class ProtoCertChainEntry : public LogEntry {
 public:
  ProtoCertChainEntry() {}
  ProtoCertChainEntry(const ProtoCertChain &chain);
  // Constructs a partially initialized entry.
  ProtoCertChainEntry(const CertChain &chain);
  ~ProtoCertChainEntry() {}

  LogEntryType Type() const { return LogEntry::PROTOCERT_CHAIN_ENTRY; }
 protected:
  // struct {
  //   struct {
  //     ASN.1Cert tbs;
  //     ASN.1Cert intermediate_chain<0..2^24-1>;
  //   } signed_part;
  //   ASN.1Cert protocert;
  //   ASN.1Cert ca_protocert;
  // } ProtoCertChainEntry;
  bool SerializeImpl(bstring *result) const;
  bool SerializeSignedImpl(bstring *result) const;
  bool DeserializeImpl(const bstring &record);
 private:
  // Signed part.
  bstring tbs_;
  std::vector<bstring> intermediates_;
  // Unsigned part;
  bstring protocert_;
  bstring ca_protocert_;
};
#endif
