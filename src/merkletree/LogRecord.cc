#include <string>

#include <assert.h>
#include <stddef.h>

#include "LogRecord.h"

namespace {

// Serialize MSB to LSB, write |bytes| least significant bytes.
std::string SerializeUint(size_t in, size_t bytes) {
  assert(bytes <= sizeof in);
  assert(in >> (8 * bytes) == 0);
  std::string result;
  for ( ; bytes > 0; --bytes)
    result.push_back((char)
                     ((in & (0xff << ((bytes - 1) * 8))) >> ((bytes - 1) * 8)));
  return result;
}

size_t DeserializeUint(const std::string &in) {
  size_t len = in.length();
  assert(len <= sizeof(size_t));
  size_t res = 0;
  for (size_t i = 0; i < len; ++i)
    res = (res << 8) + in[i];
  return res;
}

bool IsValidHashAlgorithmEnum(size_t h) {
  if (h > 6)
    return false;
  return true;
}

bool IsValidSignatureAlgorithmEnum(size_t s) {
  if (s > 3)
    return false;
  return true;
}

} // namespace

std::string DigitallySigned::Serialize() const {
  std::string result = SerializeUint(hash_algo, 1);
  result.append(SerializeUint(sig_algo, 1));
  result.append(SerializeUint(signature.size(), 2));
  result.append(signature);
  return result;
}

size_t DigitallySigned::ReadFromString(const std::string &data) {
  if (data.size() < 4)
    return 0;
  size_t h = data[0];
  size_t s = data[1];
  if (!IsValidHashAlgorithmEnum(h) || !IsValidSignatureAlgorithmEnum(s))
    return 0;

  size_t sig_size = DeserializeUint(data.substr(2,2));
  if (data.size() < 4 + sig_size)
    return 0;
  hash_algo = static_cast<HashAlgorithm>(h);
  sig_algo = static_cast<SignatureAlgorithm>(s);
  signature = data.substr(4, sig_size);
  return 4 + sig_size;
}

bool DigitallySigned::Deserialize(const std::string &data) {
  if (data.empty() || ReadFromString(data) != data.size())
    return false;
  return true;
}

std::string SegmentData::SerializeLogSegmentTreeData() const {
  std::string result(SerializeUint(LOG_SEGMENT_TREE, 1));
  result.append(SerializeUint(sequence_number, 4));
  result.append(SerializeUint(segment_size, 4));
  assert(segment_root.size() == 32);
  result.append(segment_root);
  return result;
}

std::string SegmentData::SerializeSegmentInfoTreeData() const {
  std::string result(SerializeUint(SEGMENT_INFO_TREE, 1));
  result.append(SerializeUint(sequence_number, 4));
  assert(segment_info_root.size() == 32);
  result.append(segment_info_root);
  return result;
}

std::string SegmentData::SerializeSegmentInfo() const {
  std::string result = SerializeUint(sequence_number, 4);
  result.append(SerializeUint(timestamp, 4));
  result.append(SerializeUint(segment_size, 4));
  result.append(segment_sig.Serialize());
  result.append(segment_info_sig.Serialize());
  return result;
}

bool SegmentData::DeserializeSegmentInfo(const std::string &segment_info) {
  size_t pos = 12;
  if (segment_info.size() < pos)
    return false;
  sequence_number = DeserializeUint(segment_info.substr(0, 4));
  timestamp = DeserializeUint(segment_info.substr(4, 4));
  segment_size = DeserializeUint(segment_info.substr(8,4));
  size_t sig1_size = segment_sig.ReadFromString(segment_info.substr(12));
  if (sig1_size == 0)
    return false;
  if(!segment_info_sig.Deserialize(segment_info.substr(12 + sig1_size)))
    return false;
  return true;
}
