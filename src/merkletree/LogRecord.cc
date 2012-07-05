#include <assert.h>
#include <stddef.h>

#include "../include/types.h"
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

bstring DigitallySigned::Serialize() const {
  bstring result = util::SerializeUint(hash_algo, 1);
  result.append(util::SerializeUint(sig_algo, 1));
  result.append(util::SerializeUint(sig_string.size(), 2));
  result.append(sig_string);
  return result;
}

size_t DigitallySigned::ReadFromString(const bstring &data) {
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
  if (data.size() - 4 < sig_size) {
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

bool DigitallySigned::Deserialize(const bstring &data) {
  if (data.empty() || ReadFromString(data) != data.size())
    return false;
  return true;
}

bstring LogSegmentTreeData::Serialize() const {
  bstring result(util::SerializeUint(sequence_number, 4));
  result.append(util::SerializeUint(segment_size, 4));
  assert(root.size() == 32);
  result.append(root);
  return result;
}

size_t LogSegmentTreeData::ReadFromString(const bstring &data) {
  if (data.size() < 40)
    return 0;
  sequence_number = util::DeserializeUint(data.substr(0, 4));
  segment_size = util::DeserializeUint(data.substr(4, 4));
  root = data.substr(8, 32);
  return 40;
}

bstring LogSegmentCheckpoint::Serialize() const {
  bstring result = tree_data.Serialize();
  result.append(signature.Serialize());
  return result;
}

bool LogSegmentCheckpoint::Deserialize(const bstring &data) {
  size_t tree_data_length = tree_data.ReadFromString(data);
  if (tree_data_length == 0)
    return false;
  return signature.Deserialize(data.substr(tree_data_length));
}

bstring LogHeadTreeData::Serialize() const {
  bstring result(util::SerializeUint(sequence_number, 4));
  assert(root.size() == 32);
  result.append(root);
  return result;
}

size_t LogHeadTreeData::ReadFromString(const bstring &data) {
  if (data.size() < 36)
    return 0;
  sequence_number = util::DeserializeUint(data.substr(0, 4));
  root = data.substr(4, 32);
  return 36;
}

bstring LogHeadCheckpoint::Serialize() const {
  bstring result = tree_data.Serialize();
  result.append(signature.Serialize());
  return result;
}

bool LogHeadCheckpoint::Deserialize(const bstring &data) {
  size_t tree_data_length = tree_data.ReadFromString(data);
  if (tree_data_length == 0)
    return false;
  return signature.Deserialize(data.substr(tree_data_length));
}

bstring SegmentData::SerializeSegmentInfo() const {
  assert(log_segment.tree_data.sequence_number ==
         log_head.tree_data.sequence_number);
  bstring result(util::SerializeUint(log_segment.tree_data.sequence_number, 4));
  result.append(util::SerializeUint(timestamp, 4));
  result.append(util::SerializeUint(log_segment.tree_data.segment_size, 4));
  result.append(log_segment.signature.Serialize());
  result.append(log_head.signature.Serialize());
  return result;
}

bool SegmentData::DeserializeSegmentInfo(const bstring &data) {
  size_t pos = 12;
  if (data.size() < pos)
    return false;
  log_segment.tree_data.sequence_number =
      util::DeserializeUint(data.substr(0, 4));
  log_head.tree_data.sequence_number = log_segment.tree_data.sequence_number;
  timestamp = util::DeserializeUint(data.substr(4, 4));
  log_segment.tree_data.segment_size = util::DeserializeUint(data.substr(8,4));
  size_t sig1_size = log_segment.signature.ReadFromString(data.substr(12));
  if (sig1_size == 0)
    return false;
  if(!log_head.signature.Deserialize(data.substr(12 + sig1_size)))
    return false;
  return true;
}

bstring AuditProof::Serialize() const {
  bstring result = util::SerializeUint(sequence_number, 4);
  if (proof_type == LOG_SEGMENT_PROOF)
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

bool AuditProof::Deserialize(ProofType type, const bstring &proof) {
  DLOG_BEGIN_PARSE("audit proof");
  proof_type = type;
  size_t pos = 0;
  if (proof.size() - pos < 4) {
    DLOG_ERROR("Proof too short");
    DLOG_END_PARSE;
    return false;
  }
  sequence_number = util::DeserializeUint(proof.substr(pos, 4));
  DLOG_UINT("sequence number", sequence_number);
  pos += 4;
  if (proof_type == LOG_SEGMENT_PROOF) {
    if (proof.size() - pos < 4) {
      DLOG_ERROR("Proof too short");
      DLOG_END_PARSE;
      return false;
    }
    tree_size = util::DeserializeUint(proof.substr(pos, 4));
    DLOG_UINT("tree size", tree_size);
    pos +=4;
  } else
    tree_size = sequence_number + 1;
  if (proof.size() - pos < 4) {
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
