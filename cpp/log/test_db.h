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
  std::string meta_dir = tmp_.TmpStorageDir() + "/meta";
  CHECK_ERR(mkdir(certs_dir.c_str(), 0700));
  CHECK_ERR(mkdir(tree_dir.c_str(), 0700));
  CHECK_ERR(mkdir(meta_dir.c_str(), 0700));

  db_ = new FileDB<cert_trans::LoggedCertificate>(
      new cert_trans::FileStorage(certs_dir, kCertStorageDepth),
      new cert_trans::FileStorage(tree_dir, kTreeStorageDepth),
      new cert_trans::FileStorage(meta_dir, 0));
}

template <>
FileDB<cert_trans::LoggedCertificate>*
TestDB<FileDB<cert_trans::LoggedCertificate> >::SecondDB() const {
  std::string certs_dir = this->tmp_.TmpStorageDir() + "/certs";
  std::string tree_dir = this->tmp_.TmpStorageDir() + "/tree";
  std::string meta_dir = this->tmp_.TmpStorageDir() + "/meta";
  return new FileDB<cert_trans::LoggedCertificate>(
      new cert_trans::FileStorage(certs_dir, kCertStorageDepth),
      new cert_trans::FileStorage(tree_dir, kTreeStorageDepth),
      new cert_trans::FileStorage(meta_dir, 0));
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
void TestDB<cert_trans::FileStorage>::Setup() {
  db_ = new cert_trans::FileStorage(tmp_.TmpStorageDir(), kCertStorageDepth);
}

template <>
cert_trans::FileStorage* TestDB<cert_trans::FileStorage>::SecondDB() const {
  return new cert_trans::FileStorage(tmp_.TmpStorageDir(), kCertStorageDepth);
}
#endif  // LOG_TEST_DB_H
