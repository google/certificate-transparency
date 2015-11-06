#ifndef CERT_TRANS_SERVER_SERVER_HELPER_H_
#define CERT_TRANS_SERVER_SERVER_HELPER_H_

#include <chrono>
#include <csignal>
#include <cstring>
#include <functional>
#include <gflags/gflags.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <openssl/crypto.h>

#include "base/macros.h"
#include "log/database.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/leveldb_db.h"
#include "log/sqlite_db.h"

namespace cert_trans {

// This includes code common to multiple CT servers. It handles parsing
// flags and creating objects that are used by multiple servers. Anything that
// is specific one type of CT server should not be in this class.
//
// Do not link server_helper into servers that don't use it as it will confuse
// the user with extra flags.
//
// Note methods named ProvideX create a new instance of X each call.

// Calling this will CHECK if the flag validators failed to register
void EnsureValidatorsRegistered();

// Create one of the supported database types based on flags settings
std::unique_ptr<Database> ProvideDatabase();

}  // namespace cert_trans

#endif  // CERT_TRANS_SERVER_SERVER_HELPER_H_
