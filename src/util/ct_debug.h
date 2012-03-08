#ifndef CT_DEBUG_H
#define CT_DEBUG_H

#include <assert.h>
#include <string>

#include <stdio.h>

#ifndef NDEBUG
namespace debug {

void BeginBlock(const std::string &label);
void EndBlock();

void Error(const std::string &errstr);

void UintValue(const std::string &label, size_t value);

void BinaryData(const std::string &label, const void *buf,
                size_t length);

} // namespace debug

// InitDebug should be called at most once.

static const char kClientMessage[] = "client message";
static const char kServerMessage[] = "server message";

// Convenience macros
// Caller is responsible for closing each DLOG_BEGIN with a
// corresponding DLOG_END macro.
#define DLOG_BEGIN_CLIENT_MESSAGE debug::BeginBlock(kClientMessage)
#define DLOG_BEGIN_SERVER_MESSAGE debug::BeginBlock(kServerMessage)
#define DLOG_END_CLIENT_MESSAGE debug::EndBlock()
#define DLOG_END_SERVER_MESSAGE debug::EndBlock()

#define DLOG_BEGIN_PARSE(label) debug::BeginBlock(label)
#define DLOG_END_PARSE debug::EndBlock()

#define DLOG_UINT(label, value) debug::UintValue(label, value)
#define DLOG_BINARY(label, buf, size) debug::BinaryData(label, buf, size)
#define DLOG_ERROR(errstr) debug::Error(errstr)
#else // NDEBUG
#define DLOG_BEGIN_CLIENT_MESSAGE
#define DLOG_BEGIN_SERVER_MESSAGE
#define DLOG_END_CLIENT_MESSAGE
#define DLOG_END_SERVER_MESSAGE

#define DLOG_BEGIN_PARSE(label)
#define DLOG_END_PARSE

#define DLOG_UINT(label, value)
#define DLOG_BINARY(label, buf, size)
#define DLOG_ERROR(errstr)
#endif

// Write debugging info to std::cout
void InitDebug();

// Write debugging info to file.
void InitDebug(const char *filename);
#endif
