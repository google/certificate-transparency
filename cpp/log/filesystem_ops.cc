#include "log/filesystem_ops.h"

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

namespace cert_trans {


int BasicFilesystemOps::mkdir(const char* path, mode_t mode) {
  return ::mkdir(path, mode);
}


int BasicFilesystemOps::remove(const char* path) {
  return ::remove(path);
}


int BasicFilesystemOps::rename(const char* old_name, const char* new_name) {
  return ::rename(old_name, new_name);
}


int BasicFilesystemOps::access(const char* path, int amode) {
  return ::access(path, amode);
}


FailingFilesystemOps::FailingFilesystemOps(int fail_point)
    : op_count_(0), fail_point_(fail_point) {
}


int FailingFilesystemOps::mkdir(const char* path, mode_t mode) {
  if (fail_point_ == op_count_++) {
    errno = EIO;
    return -1;
  }
  return ::mkdir(path, mode);
}


int FailingFilesystemOps::remove(const char* path) {
  if (fail_point_ == op_count_++) {
    errno = EIO;
    return -1;
  }
  return ::remove(path);
}


int FailingFilesystemOps::rename(const char* old_name, const char* new_name) {
  if (fail_point_ == op_count_++) {
    errno = EIO;
    return -1;
  }
  return ::rename(old_name, new_name);
}


int FailingFilesystemOps::access(const char* path, int amode) {
  if (fail_point_ == op_count_++) {
    errno = EACCES;
    return -1;
  }
  return ::access(path, amode);
}


}  // namespace cert_trans
