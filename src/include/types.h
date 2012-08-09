#ifndef CT_TYPES_H
#define CT_TYPES_H

#include <google/protobuf/repeated_field.h>
#include <string>

typedef char byte;
typedef std::string bstring;
typedef ::google::protobuf::RepeatedPtrField<std::string> repeated_string;
#endif
