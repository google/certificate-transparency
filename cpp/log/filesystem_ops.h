#ifndef FILESYSTEM_OP_H
#define FILESYSTEM_OP_H

#include <sys/types.h>

#include "base/macros.h"

namespace cert_trans {


// Make filesystem operations virtual so that we can override
// to simulate filesystem errors.
class FilesystemOps {
 public:
  virtual ~FilesystemOps() = default;

  virtual int mkdir(const char* path, mode_t mode) = 0;
  virtual int remove(const char* path) = 0;
  virtual int rename(const char* old_name, const char* new_name) = 0;
  virtual int access(const char* path, int amode) = 0;

 protected:
  FilesystemOps() = default;

 private:
  DISALLOW_COPY_AND_ASSIGN(FilesystemOps);
};


class BasicFilesystemOps : public FilesystemOps {
 public:
  BasicFilesystemOps() = default;

  int mkdir(const char* path, mode_t mode) override;
  int remove(const char* path) override;
  int rename(const char* old_name, const char* new_name) override;
  int access(const char* path, int amode) override;
};


// Fail at an operation with a given op count.
class FailingFilesystemOps : public FilesystemOps {
 public:
  explicit FailingFilesystemOps(int fail_point);

  int OpCount() const {
    return op_count_;
  }

  int mkdir(const char* path, mode_t mode) override;
  int remove(const char* path) override;
  int rename(const char* old_name, const char* new_name) override;
  int access(const char* path, int amode) override;

 private:
  int op_count_;
  int fail_point_;
};


}  // namespace cert_trans

#endif
