#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string>

#include "ct_debug.h"
#include "types.h"
#include "util.h"


#ifndef NDEBUG

namespace {
// Really just a logger, but we don't want to overload the term "log".
class CTDebugger {
 public:
  CTDebugger() : stream_(&std::cout), wants_erase_(false), nested_level_(-1) { }
  CTDebugger(const char *file) : nested_level_(-1) {
    std::ofstream *out = new std::ofstream(file);
    if (!out->is_open()) {
      perror(file);
      exit(1);
    }
    stream_ = static_cast<std::ostream*>(out);
    wants_erase_ = true;
  }

  ~CTDebugger()  {
    if (wants_erase_) {
      delete stream_;
    }
  }

  void BeginBlock(const std::string &label) {
    if (nested_level_ == -1) {
    PrintStringLine(kDelimiter);
    PrintStringLine(label);
    PrintStringLine(kDelimiter);
    } else {
      PrintTab();
      *stream_ << label << ":" << std::endl;
    }
    ++nested_level_;
  }

  void EndBlock() {
    assert(nested_level_ >= 0);
    --nested_level_;
    if (nested_level_ == -1)
      PrintStringLine(kDelimiter);
  }

  void Error(const std::string &error) {
    *stream_ << "ERROR: " << error << std::endl;
  }

  void UintValue(const std::string &label, size_t value) {
    PrintTab();
    *stream_ << label << ": " << value << std::endl;
  }

  void BinaryData(const std::string &label, const bstring &data) {
    PrintTab();
    const std::string unit = data.size() == 1 ? "byte" : "bytes";
    *stream_ << label << " (" << data.size() << " " << unit << "):"
             << std::endl;
    for (size_t i = 0; i < data.size(); i += 20) {
      PrintTab();
      *stream_ << util::HexString(data.substr(i, 20), ' ') << std::endl;
    }
  }

 private:
  void PrintTab() {
    assert(nested_level_ >= 0);
    *stream_ << std::string(nested_level_ * 2, ' ');
  }

  void PrintStringLine(const std::string &str) {
    *stream_ << str << std::endl;
  }

  std::ostream *stream_;
  bool wants_erase_;
  int nested_level_;
  static const char kDelimiter[];
};

const char CTDebugger::kDelimiter[] =
    "----------------------------------------"
    "----------------------------------------";

CTDebugger *debugger = NULL;
bool debugger_initialized = false;

}

namespace debug {

void BeginBlock(const std::string &label) {
  if (debugger_initialized)
    debugger->BeginBlock(label);
}

void EndBlock() {
  if (debugger_initialized)
    debugger->EndBlock();
}

void Error(const std::string &errstr) {
  if (debugger_initialized)
    debugger->Error(errstr);
}

void UintValue(const std::string &name, size_t value) {
  if (debugger_initialized)
    debugger->UintValue(name, value);
}

void BinaryData(const std::string &label, const void *buf, size_t length) {
  if (debugger_initialized)
    debugger->BinaryData(label,
                         bstring(static_cast<const byte*>(buf),
                                 length));
}

} // namespace debug

void InitDebug() {
  assert(!debugger_initialized);
  // This will never be freed.
  debugger = new CTDebugger();
  debugger_initialized = true;
}

void InitDebug(const char *filename) {
  assert(!debugger_initialized);
  // This will never be freed.
  debugger = new CTDebugger(filename);
  debugger_initialized = true;
}

#else
static const char[] kDebugWarning = "WARNING: debugging info is disabled.";

void InitDebug() {
  std::cout << kDebugWarning << std::endl;
}

void InitDebug(const char *filename) {
    std::ofstream out(file);
    if (!out->is_open()) {
      perror(file);
      exit(1);
    }
    out << kDebugWarning << std::endl;
}
#endif
