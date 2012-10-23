#ifndef CT_H
#define CT_H

namespace ct {

// Serialized packet format:
// version - 1 byte
// format - 1 byte
// length - 3 bytes
// data - |length| bytes

// One byte when serialized.
enum MessageFormat {
  PROTOBUF = 0,
};

}  // namespace
#endif
