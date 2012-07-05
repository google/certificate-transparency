#ifndef LOGRECORD_H
#define LOGRECORD_H

#include <stddef.h>
#include <vector>

#include "../include/types.h"

// RFC5246.
struct DigitallySigned {
  // One byte.
  enum HashAlgorithm {
    NONE = 0,
    MD5 = 1,
    SHA1 = 2,
    SHA224 = 3,
    SHA256 = 4,
    SHA384 = 5,
    SHA512 = 6,
  };
  // One byte.
  enum SignatureAlgorithm {
    ANONYMOUS = 0,
    RSA = 1,
    DSA = 2,
    ECDSA = 3,
  };
  HashAlgorithm hash_algo;
  SignatureAlgorithm sig_algo;
  bstring sig_string;
  // Serialized format:
  // uint8 hash_algo;
  // uint8 sig_algo;
  // opaque signature<0..2^16-1>
  bstring Serialize() const;
  // Like Deserialize, but the input string can be longer.
  // Returns the number of consumed bytes if the beginning
  // of the string encodes a valid signature, and 0 otherwise.
  size_t ReadFromString(const bstring &data);
  bool Deserialize(const bstring &data);
};

struct LogSegmentTreeData {
  size_t sequence_number;
  size_t segment_size;
  bstring root;
  // Input to segment_sig.
  // Serialized format:
  // struct {
  //   uint32 sequence_number;
  //   uint32 segment_size;
  //   opaque segment_root[32];
  // } LogSegmentTreeData;
  bstring Serialize() const;
  size_t ReadFromString(const bstring &data);
};

struct LogSegmentCheckpoint {
  LogSegmentTreeData tree_data;
  DigitallySigned signature;
  bstring Serialize() const;
  bool Deserialize(const bstring &data);
};

struct LogHeadTreeData {
  size_t sequence_number;
  bstring root;
  // Input to segment_info_sig.
  // Serialized format:
  // struct {
  //   uint32 sequence_number;
  //   opaque segment_info_root[32];
  // } LogHeadTreeData;
  bstring Serialize() const;
  size_t ReadFromString(const bstring &data);
};

struct LogHeadCheckpoint {
  LogHeadTreeData tree_data;
  DigitallySigned signature;
  bstring Serialize() const;
  bool Deserialize(const bstring &data);
};

struct SegmentData {
  size_t timestamp;
  // log_segment.sequence_number = log_head.sequence_number
  LogSegmentCheckpoint log_segment;
  LogHeadCheckpoint log_head;

  // The SegmentInfo log record.
  // Serialized format:
  // struct {
  //   uint32 sequence_number;
  //   uint32 timestamp;
  //   uint32 segment_size;
  //   DigitallySigned segment_sig;
  //   DigitallySigned segment_info_sig;
  // } SegmentInfo;
  bstring SerializeSegmentInfo() const;

  // Parse the SegmentInfo record from a string. If the encoding is valid,
  // return true and populate the fields; else return false.
  bool DeserializeSegmentInfo(const bstring &segment_info);
};

struct AuditProof {
  enum ProofType {
    LOG_SEGMENT_PROOF,
    LOG_HEAD_PROOF,
  };
  ProofType proof_type;
  size_t sequence_number;
  size_t tree_size;
  size_t leaf_index;
  DigitallySigned signature;
  std::vector<bstring> audit_path;
  bstring Serialize() const;
  bool Deserialize(ProofType type, const bstring &data);
};
#endif
