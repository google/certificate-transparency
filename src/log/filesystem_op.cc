#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "log/filesystem_op.h"

BasicFilesystemOp::BasicFilesystemOp() {}

int BasicFilesystemOp::mkdir(const char *path, mode_t mode) {
  return ::mkdir(path, mode);
}

int BasicFilesystemOp::remove(const char *path) {
  return ::remove(path);
}

int BasicFilesystemOp::rename(const char *old_name, const char *new_name) {
  return ::rename(old_name, new_name);
}

int BasicFilesystemOp::access(const char *path, int amode) {
  return ::access(path, amode);
}

FailingFilesystemOp::FailingFilesystemOp(int fail_point)
    : op_count_(0),
      fail_point_(fail_point) {}

int FailingFilesystemOp::mkdir(const char *path, mode_t mode) {
  if (fail_point_ == op_count_++) {
    errno = EIO;
    return -1;
  }
  return ::mkdir(path, mode);
}

int FailingFilesystemOp::remove(const char *path) {
  if (fail_point_ == op_count_++) {
    errno = EIO;
    return -1;
  }
  return ::remove(path);
}

int FailingFilesystemOp::rename(const char *old_name, const char *new_name) {
  if (fail_point_ == op_count_++) {
    errno = EIO;
    return -1;
  }
  return ::rename(old_name, new_name);
}

int FailingFilesystemOp::access(const char *path, int amode) {
  if (fail_point_ == op_count_++) {
    errno = EACCES;
    return -1;
  }
  return ::access(path, amode);
}
