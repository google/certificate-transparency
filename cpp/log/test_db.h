/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef LOG_TEST_DB_H
#define LOG_TEST_DB_H

#include <sys/stat.h>

#include "util/test_db.h"
#include "log/database.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/logged_certificate.h"
#include "log/sqlite_db.h"

static const unsigned kCertStorageDepth = 3;
static const unsigned kTreeStorageDepth = 8;

template <>
void TestDB<FileDB<cert_trans::LoggedCertificate> >::Setup() {
  std::string certs_dir = tmp_.TmpStorageDir() + "/certs";
  std::string tree_dir = tmp_.TmpStorageDir() + "/tree";
  CHECK_ERR(mkdir(certs_dir.c_str(), 0700));
  CHECK_ERR(mkdir(tree_dir.c_str(), 0700));

  db_ = new FileDB<cert_trans::LoggedCertificate>(
      new FileStorage(certs_dir, kCertStorageDepth),
      new FileStorage(tree_dir, kTreeStorageDepth));
}

template <>
FileDB<cert_trans::LoggedCertificate>*
TestDB<FileDB<cert_trans::LoggedCertificate> >::SecondDB() const {
  std::string certs_dir = this->tmp_.TmpStorageDir() + "/certs";
  std::string tree_dir = this->tmp_.TmpStorageDir() + "/tree";
  return new FileDB<cert_trans::LoggedCertificate>(
      new FileStorage(certs_dir, kCertStorageDepth),
      new FileStorage(tree_dir, kTreeStorageDepth));
}

template <>
void TestDB<SQLiteDB<cert_trans::LoggedCertificate> >::Setup() {
  db_ = new SQLiteDB<cert_trans::LoggedCertificate>(tmp_.TmpStorageDir() +
                                                    "/sqlite");
}

template <>
SQLiteDB<cert_trans::LoggedCertificate>*
TestDB<SQLiteDB<cert_trans::LoggedCertificate> >::SecondDB() const {
  return new SQLiteDB<cert_trans::LoggedCertificate>(tmp_.TmpStorageDir() +
                                                     "/sqlite");
}

// Not a Database; we just use the same template for setup.
template <>
void TestDB<FileStorage>::Setup() {
  db_ = new FileStorage(tmp_.TmpStorageDir(), kCertStorageDepth);
}

template <>
FileStorage* TestDB<FileStorage>::SecondDB() const {
  return new FileStorage(tmp_.TmpStorageDir(), kCertStorageDepth);
}
#endif  // LOG_TEST_DB_H
