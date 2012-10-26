#ifndef CT_H
#define CT_H

namespace ct {
namespace protocol {

// Serialized packet format:
// version - 1 byte
// format - 1 byte
// length - 3 bytes
// data - |length| bytes

// One byte when serialized.
enum Version {
  V1 = 0,
};

// One byte when serialized.
enum Format {
  PROTOBUF = 0,
};

const size_t kPacketPrefixLength = 3;
const size_t kMaxPacketLength = (1 << 24) - 1;

}  // namespace protocol
}  // namespace ct
#endif
