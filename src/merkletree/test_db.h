#ifndef TEST_DB_H
#define TEST_DB_H

#include <assert.h>
#include <iostream>
#include <string>

#include "log_db.h"
#include "util.h"

// Helper classes that provide a unified interface for setting up typed tests.
class TestMemoryDB {
 public:
  TestMemoryDB() {}
  ~TestMemoryDB() {}

  // Caller owns result.
  LogDB *GetDB() const { return new MemoryDB(); }
};

class TestFileDB {
 public:
  TestFileDB() {
    file_base_ = util::CreateTemporaryDirectory("/tmp/ctlogXXXXXX");
    if (file_base_.empty())
      std::cout << "Could not create temporary directory in /tmp" << std::endl;
  }

  ~TestFileDB() {
    if (!file_base_.empty()) {
      std::string command = "rm -r " + file_base_;
      int ret = system(command.c_str());
      // Can't ignore the return value.
      ret = ret;
    }
  }

  // Caller owns result.
  // Can be called multiple times to resurrect the DB from disk.
  LogDB *GetDB() const {
    if (file_base_.empty())
      return NULL;
    FileDB *db = new FileDB(file_base_, 5);
    db->Init();
    return db;
  }

 private:
  std::string file_base_;
};
#endif
