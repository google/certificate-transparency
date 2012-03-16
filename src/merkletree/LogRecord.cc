#include <string>

#include <assert.h>
#include <stddef.h>

#include "../util/ct_debug.h"
#include "../util/util.h"
#include "LogRecord.h"

static bool IsValidHashAlgorithmEnum(size_t h) {
  if (h > 6)
    return false;
  return true;
}

static bool IsValidSignatureAlgorithmEnum(size_t s) {
  if (s > 3)
    return false;
  return true;
}

std::string DigitallySigned::Serialize() const {
  std::string result = util::SerializeUint(hash_algo, 1);
  result.append(util::SerializeUint(sig_algo, 1));
  result.append(util::SerializeUint(sig_string.size(), 2));
  result.append(sig_string);
  return result;
}

size_t DigitallySigned::ReadFromString(const std::string &data) {
  DLOG_BEGIN_PARSE("signature");
  if (data.size() < 4) {
    DLOG_ERROR("Signature too short");
    DLOG_END_PARSE;
    return 0;
  }
  size_t h = data[0];
  DLOG_UINT("hash algorithm", h);
  size_t s = data[1];
  DLOG_UINT("signature algorithm", s);
  if (!IsValidHashAlgorithmEnum(h) || !IsValidSignatureAlgorithmEnum(s)) {
    DLOG_ERROR("Invalid algorithm");
    DLOG_END_PARSE;
    return 0;
  }

  size_t sig_size = util::DeserializeUint(data.substr(2,2));
  DLOG_UINT("signature size", sig_size);
  if (data.size() < 4 + sig_size) {
    DLOG_ERROR("Signature too short");
    DLOG_END_PARSE;
    return 0;
  }
  hash_algo = static_cast<HashAlgorithm>(h);
  sig_algo = static_cast<SignatureAlgorithm>(s);
  sig_string = data.substr(4, sig_size);
  DLOG_BINARY("signature", sig_string.data(), sig_string.size());
  DLOG_END_PARSE;
  return 4 + sig_size;
}

bool DigitallySigned::Deserialize(const std::string &data) {
  if (data.empty() || ReadFromString(data) != data.size())
    return false;
  return true;
}

std::string LogSegmentCheckpoint::Serialize() const {
  std::string result = util::SerializeUint(sequence_number, 4);
  result.append(util::SerializeUint(segment_size, 4));
  result.append(signature.Serialize());
  assert(root.size() == 32);
  result.append(root);
  return result;
}

std::string LogSegmentCheckpoint::SerializeTreeData() const {
  std::string result(util::SerializeUint(SegmentData::LOG_SEGMENT_TREE, 1));
  result.append(util::SerializeUint(sequence_number, 4));
  result.append(util::SerializeUint(segment_size, 4));
  assert(root.size() == 32);
  result.append(root);
  return result;
}

bool LogSegmentCheckpoint::Deserialize(const std::string &data) {
  if (data.size() < 8)
    return false;
  sequence_number = util::DeserializeUint(data.substr(0, 4));
  segment_size = util::DeserializeUint(data.substr(4, 4));
  size_t pos = 8;
  size_t sig_size =signature.ReadFromString(data.substr(pos));
  if (sig_size == 0)
    return false;
  pos += sig_size;
  if (data.size() != pos + 32)
    return false;
  root = data.substr(pos);
  return true;
}

std::string LogHeadCheckpoint::Serialize() const {
  std::string result = util::SerializeUint(sequence_number, 4);
  result.append(signature.Serialize());
  assert(root.size() == 32);
  result.append(root);
  return result;
}

std::string LogHeadCheckpoint::SerializeTreeData() const {
  std::string result(util::SerializeUint(SegmentData::SEGMENT_INFO_TREE, 1));
  result.append(util::SerializeUint(sequence_number, 4));
  assert(root.size() == 32);
  result.append(root);
  return result;
}

bool LogHeadCheckpoint::Deserialize(const std::string &data) {
  if (data.size() < 4)
    return false;
  sequence_number = util::DeserializeUint(data.substr(0, 4));
  size_t pos = 4;
  size_t sig_size = signature.ReadFromString(data.substr(pos));
  if (sig_size == 0)
    return false;
  pos += sig_size;
  if (data.size() != pos + 32)
    return false;
  root = data.substr(pos);
  return true;
}

std::string SegmentData::SerializeSegmentInfo() const {
  assert(log_segment.sequence_number == log_head.sequence_number);
  std::string result = util::SerializeUint(log_segment.sequence_number, 4);
  result.append(util::SerializeUint(timestamp, 4));
  result.append(util::SerializeUint(log_segment.segment_size, 4));
  result.append(log_segment.signature.Serialize());
  result.append(log_head.signature.Serialize());
  return result;
}

bool SegmentData::DeserializeSegmentInfo(const std::string &data) {
  size_t pos = 12;
  if (data.size() < pos)
    return false;
  log_segment.sequence_number = util::DeserializeUint(data.substr(0, 4));
  log_head.sequence_number = log_segment.sequence_number;
  timestamp = util::DeserializeUint(data.substr(4, 4));
  log_segment.segment_size = util::DeserializeUint(data.substr(8,4));
  size_t sig1_size = log_segment.signature.ReadFromString(data.substr(12));
  if (sig1_size == 0)
    return false;
  if(!log_head.signature.Deserialize(data.substr(12 + sig1_size)))
    return false;
  return true;
}

std::string AuditProof::Serialize() const {
  std::string result = util::SerializeUint(sequence_number, 4);
  if (tree_type == SegmentData::LOG_SEGMENT_TREE)
    result.append(util::SerializeUint(tree_size, 4));
  result.append(util::SerializeUint(leaf_index, 4));
  result.append(signature.Serialize());
  for (size_t i = 0; i < audit_path.size(); ++i) {
    // Hard-code sha256.
    assert(audit_path[i].size() == 32);
    result.append(audit_path[i]);
  }
  return result;
}

bool AuditProof::Deserialize(SegmentData::TreeType type,
                             const std::string &proof) {
  DLOG_BEGIN_PARSE("audit proof");
  tree_type = type;
  size_t pos = 0;
  if (proof.size() < pos + 4) {
    DLOG_ERROR("Proof too short");
    DLOG_END_PARSE;
    return false;
  }
  sequence_number = util::DeserializeUint(proof.substr(pos, 4));
  DLOG_UINT("sequence number", sequence_number);
  pos += 4;
  if (tree_type == SegmentData::LOG_SEGMENT_TREE) {
    if (proof.size() < pos + 4) {
      DLOG_ERROR("Proof too short");
      DLOG_END_PARSE;
      return false;
    }
    tree_size = util::DeserializeUint(proof.substr(pos, 4));
    DLOG_UINT("tree size", tree_size);
    pos +=4;
  } else
    tree_size = sequence_number + 1;
  if (proof.size() < pos + 4) {
    DLOG_ERROR("Proof too short");
    DLOG_END_PARSE;
    return false;
  }
  leaf_index = util::DeserializeUint(proof.substr(pos, 4));
  DLOG_UINT("leaf index", leaf_index);
  pos += 4;
  size_t sig_size = signature.ReadFromString(proof.substr(pos));
  if (sig_size == 0) {
    DLOG_ERROR("Failed to parse signature");
    DLOG_END_PARSE;
    return false;
  }
  pos += sig_size;
  if (proof.substr(pos).size() % 32) {
    DLOG_ERROR("Failed to parse audit path");
    DLOG_END_PARSE;
    return false;
  }
  audit_path.clear();
  DLOG_BEGIN_PARSE("audit path");
  while (!proof.substr(pos).empty()) {
    audit_path.push_back(proof.substr(pos, 32));
    DLOG_BINARY("node", audit_path.back().data(), audit_path.back().size());
    pos += 32;
  }
  DLOG_END_PARSE;
  DLOG_END_PARSE;
  return true;
}
