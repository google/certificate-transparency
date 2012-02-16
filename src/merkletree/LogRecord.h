#ifndef LOGRECORD_H
#define LOGRECORD_H

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
  std::string signature;
  // Serialized format:
  // uint8 hash_algo;
  // uint8 sig_algo;
  // opaque signature<0..2^16-1>
  std::string Serialize() const;
  // Like Deserialize, but the input string can be longer.
  // Returns the number of consumed bytes if the beginning
  // of the string encodes a valid signature, and 0 otherwise.
  size_t ReadFromString(const std::string &data);
  bool Deserialize(const std::string &data);
};

struct SegmentData {
  // One byte.
  enum TreeType {
    LOG_SEGMENT_TREE = 0,
    SEGMENT_INFO_TREE = 1,
  };

  size_t sequence_number;
  size_t timestamp;
  size_t segment_size;
  std::string segment_root;
  std::string segment_info_root;
  DigitallySigned segment_sig; // signature on LogSegmentTreeData
  DigitallySigned segment_info_sig; // signature on SegmentInfoTreeData

  // Input to segment_sig.
  // Serialized format:
  // struct {
  //   uint8 tree_type = LOG_SEGMENT;
  //   uint32 sequence_number;
  //   uint32 tree_size;
  //   opaque segment_root[32];
  // } LogSegmentTreeData;
  std::string SerializeLogSegmentTreeData() const;

  // Input to segment_info_sig.
  // Serialized format:
  // struct {
  //   uint8 tree_type = SEGMENT_INFO;
  //   uint32 sequence_number;
  //   opaque segment_info_root[32];
  // } SegmentInfoTreeData;
  std::string SerializeSegmentInfoTreeData() const;

  // The SegmentInfo log record.
  // Serialized format:
  // struct {
  //   uint32 sequence_number;
  //   uint32 timestamp;
  //   uint32 segment_size;
  //   DigitallySigned segment_sig;
  //   DigitallySigned segment_info_sig;
  // } SegmentInfo;
  std::string SerializeSegmentInfo() const;

  // Parse the SegmentInfo record from a string. If the encoding is valid,
  // return true and populate the fields; else return false.
  bool DeserializeSegmentInfo(const std::string &segment_info);
};
#endif
