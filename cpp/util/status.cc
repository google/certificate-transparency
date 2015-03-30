// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <sstream>

#include "util/status.h"

using ::std::ostream;
using ::std::string;

namespace util {

namespace {


const Status& GetOk() {
  static const Status status;
  return status;
}

const Status& GetCancelled() {
  static const Status status(::util::error::CANCELLED, "");
  return status;
}

const Status& GetUnknown() {
  static const Status status(::util::error::UNKNOWN, "");
  return status;
}


}  // namespace


Status::Status() : code_(::util::error::OK), message_("") {
}

Status::Status(::util::error::Code error, const string& error_message)
    : code_(error), message_(error_message) {
  if (code_ == ::util::error::OK) {
    message_.clear();
  }
}

Status::Status(const Status& other)
    : code_(other.code_), message_(other.message_) {
}

Status& Status::operator=(const Status& other) {
  code_ = other.code_;
  message_ = other.message_;
  return *this;
}

const Status& Status::OK = GetOk();
const Status& Status::CANCELLED = GetCancelled();
const Status& Status::UNKNOWN = GetUnknown();

string Status::ToString() const {
  if (code_ == ::util::error::OK) {
    return "OK";
  }

  std::ostringstream oss;
  oss << code_ << ": " << message_;
  return oss.str();
}

extern ostream& operator<<(ostream& os, util::error::Code code) {
  switch (code) {
    case util::error::OK:
      os << "OK";
      break;
    case util::error::CANCELLED:
      os << "CANCELLED";
      break;
    case util::error::UNKNOWN:
      os << "UNKNOWN";
      return os;
    case util::error::INVALID_ARGUMENT:
      os << "INVALID_ARGUMENT";
      return os;
    case util::error::DEADLINE_EXCEEDED:
      os << "DEADLINE_EXCEEDED";
      return os;
    case util::error::NOT_FOUND:
      os << "NOT_FOUND";
      return os;
    case util::error::ALREADY_EXISTS:
      os << "ALREADY_EXISTS";
      return os;
    case util::error::PERMISSION_DENIED:
      os << "PERMISSION_DENIED";
      return os;
    case util::error::RESOURCE_EXHAUSTED:
      os << "RESOURCE_EXHAUSTED";
      return os;
    case util::error::FAILED_PRECONDITION:
      os << "FAILED_PRECONDITION";
      return os;
    case util::error::ABORTED:
      os << "ABORTED";
      return os;
    case util::error::OUT_OF_RANGE:
      os << "OUT_OF_RANGE";
      return os;
    case util::error::UNIMPLEMENTED:
      os << "UNIMPLEMENTED";
      return os;
    case util::error::INTERNAL:
      os << "INTERNAL";
      return os;
    case util::error::UNAVAILABLE:
      os << "UNAVAILABLE";
      return os;
    case util::error::DATA_LOSS:
      os << "DATA_LOSS";
      return os;
  }
  // Avoid using a "default" in the switch, so that the compiler can
  // give us a warning, but still provide a fallback here.
  os << static_cast<int>(code);
  return os;
}

extern ostream& operator<<(ostream& os, const Status& other) {
  os << other.ToString();
  return os;
}


}  // namespace util
