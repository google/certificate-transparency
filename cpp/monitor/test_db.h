#ifndef CERT_TRANS_MONITOR_TEST_DB_H_
#define CERT_TRANS_MONITOR_TEST_DB_H_

#include "monitor/sqlite_db.h"
#include "util/test_db.h"

template <>
void TestDB<monitor::SQLiteDB>::Setup() {
  db_.reset(new monitor::SQLiteDB(tmp_.TmpStorageDir() + "/sqlite"));
}

template <>
monitor::SQLiteDB* TestDB<monitor::SQLiteDB>::SecondDB() {
  return new monitor::SQLiteDB(tmp_.TmpStorageDir() + "/sqlite");
}

#endif  // CERT_TRANS_MONITOR_TEST_DB_H_
