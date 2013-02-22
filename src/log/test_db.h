/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef TEST_DB_H
#define TEST_DB_H

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <string>

#include "log/database.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/logged_certificate.h"
#include "log/sqlite_db.h"
#include "util/util.h"

DEFINE_string(database_test_dir, "/tmp",
              "Test directory for databases that use the disk. We attempt to "
              "remove all created files and directories but data may be left "
              "behind if the program does not exit cleanly.");

static const unsigned kCertStorageDepth = 3;
static const unsigned kTreeStorageDepth = 8;

class TmpStorage {
 public:
  TmpStorage()
      : tmp_dir_(FLAGS_database_test_dir) {
    file_base_ = util::CreateTemporaryDirectory(tmp_dir_ + "/ctlogXXXXXX");
    CHECK_EQ(tmp_dir_ + "/ctlog", file_base_.substr(0, tmp_dir_.size() + 6));
    CHECK_EQ(tmp_dir_.size() + 12, file_base_.length());
  }

  ~TmpStorage() {
  // Check again that it is safe to empty file_base_.
    CHECK_EQ(tmp_dir_ + "/ctlog", file_base_.substr(0, tmp_dir_.size() + 6));
    CHECK_EQ(tmp_dir_.size() + 12, file_base_.length());

    std::string command = "rm -r " + file_base_;
    CHECK_ERR(system(command.c_str()))
              << "Failed to delete temporary directory in " << file_base_;
  }

  std::string TmpStorageDir() const { return file_base_; }
 private:
  std::string tmp_dir_;
  std::string file_base_;
};

// Helper for generating test instances of the databases for typed tests.
template <class T>
class TestDB {
 public:
  TestDB()
      : tmp_() {
    Setup();
  }

  ~TestDB() {
    if (db_ != NULL)
      delete db_;
  }

  void Setup();

  T *db() const { return db_; }

  // Build a second database from the current disk state. Caller owns result.
  // Meant to be used for testing resumes from disk.
  // Concurrent behaviour is undefined (depends on the Database implementation).
  T *SecondDB() const;

 private:
  TmpStorage tmp_;
  T *db_;
};

template <> void TestDB<FileDB<ct::LoggedCertificate> >::Setup() {
  std::string certs_dir = tmp_.TmpStorageDir() + "/certs";
  std::string tree_dir = tmp_.TmpStorageDir() + "/tree";
  CHECK_ERR(mkdir(certs_dir.c_str(), 0700));
  CHECK_ERR(mkdir(tree_dir.c_str(), 0700));

  db_ = new FileDB<ct::LoggedCertificate>(
      new FileStorage(certs_dir, kCertStorageDepth),
      new FileStorage(tree_dir, kTreeStorageDepth));
}

template <> FileDB<ct::LoggedCertificate> *
TestDB<FileDB<ct::LoggedCertificate> >::SecondDB() const {
  std::string certs_dir = this->tmp_.TmpStorageDir() + "/certs";
  std::string tree_dir = this->tmp_.TmpStorageDir() + "/tree";
  return new FileDB<ct::LoggedCertificate>(new FileStorage(certs_dir,
                                                           kCertStorageDepth),
                                           new FileStorage(tree_dir,
                                                           kTreeStorageDepth));
}

template <> void TestDB<SQLiteDB<ct::LoggedCertificate> >::Setup() {
  db_ = new SQLiteDB<ct::LoggedCertificate>(tmp_.TmpStorageDir() + "/sqlite");
}

template <> SQLiteDB<ct::LoggedCertificate> *
TestDB<SQLiteDB<ct::LoggedCertificate> >::SecondDB() const {
  return new SQLiteDB<ct::LoggedCertificate>(tmp_.TmpStorageDir() + "/sqlite");
}

// Not a Database; we just use the same template for setup.
template <> void TestDB<FileStorage>::Setup() {
  db_ = new FileStorage(tmp_.TmpStorageDir(), kCertStorageDepth);
}

template <> FileStorage *TestDB<FileStorage>::SecondDB() const {
  return new FileStorage(tmp_.TmpStorageDir(), kCertStorageDepth);
}
#endif
