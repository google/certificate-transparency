#ifndef MONITOR_H
#define MONITOR_H

#include <stdint.h>
#include <string>

#include "client/http_log_client.h"
#include "monitor/sqlite_db.h"

class LogVerifier;
class Database;

namespace monitor {

class Monitor
{
 public:
  enum GetResult {
    OK = 0,
    NETWORK_PROBLEM = 1,
  };

  enum VerifyResult {
    SIGNATURE_VALID = 0,
    SIGNATURE_INVALID = 1,
    // The STH is malformed (i.e. timestamp in the future)
    // but its signature is valid.
    STH_MALFORMED_WTH_VALID_SIGNATURE = 2,
  };

  enum ConfirmResult {
    TREE_CONFIRMED = 0,
    TREE_CONFIRMATION_FAILED = 1,
  };

  Monitor(Database *database,
          LogVerifier *verifier,
          const HTTPLogClient &client,
          uint64_t sleep_time_sec);

  GetResult GetSTH();

  VerifyResult VerifySTH(uint64_t timestamp);

  GetResult GetEntries(int get_first, int get_last);

  ConfirmResult ConfirmTree(uint64_t timestamp);

  void Init();

  void Loop();

  static std::string GetResultString(GetResult result) {
    switch(result) {
      case OK:
        return "OK";
      case NETWORK_PROBLEM:
        return "Network problem";
      default:
        assert(false);
        return "Unknown";
    }
  }

 private:
  enum CheckResult {
    EQUAL = 0,
    SANE = 1,
    INSANE = 2,
    REFRESHED = 3,
  };

  Database *db_;
  LogVerifier *verifier_;
  HTTPLogClient client_;
  uint64_t sleep_time_;

  VerifyResult VerifySTHInternal();
  VerifyResult VerifySTHInternal(const ct::SignedTreeHead &sth);

  ConfirmResult ConfirmTreeInternal();
  ConfirmResult ConfirmTreeInternal(const ct::SignedTreeHead &sth);

  // Checks if two (subsequent) STHs are sane regarding timestamp and tree size.
  // Prerequisite: Both STHs should have a valid signature and not be malformed.
  // Only used internaly in loop().
  CheckResult CheckSTHSanity(const ct::SignedTreeHead &old_sth,
                             const ct::SignedTreeHead &new_sth);

  VerifyResult VerifySTHWithInvalidTimestamp(const ct::SignedTreeHead &sth);
};

} // namespace monitor

#endif // MONITOR_H
