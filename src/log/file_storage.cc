/* -*- indent-tabs-mode: nil -*- */

#include <dirent.h>
#include <errno.h>
#include <set>
#include <string>
#include <sys/stat.h>

#include "file_storage.h"
#include "filesystem_op.h"
#include "types.h"
#include "util.h"

FileStorage::FileStorage(const std::string &file_base, unsigned storage_depth)
    : storage_dir_(file_base + "/storage"),
      tmp_dir_(file_base + "/tmp"),
      tmp_file_template_(tmp_dir_ + "/tmpXXXXXX"),
      storage_depth_(storage_depth),
      file_op_(new BasicFilesystemOp()) {
  assert(storage_depth_ >= 0);
  CreateMissingDirectory(storage_dir_);
  CreateMissingDirectory(tmp_dir_);
}

FileStorage::FileStorage(const std::string &file_base, unsigned storage_depth,
                         FilesystemOp *file_op)
    : storage_dir_(file_base + "/storage"),
      tmp_dir_(file_base + "/tmp"),
      tmp_file_template_(tmp_dir_ + "/tmpXXXXXX"),
      storage_depth_(storage_depth),
      file_op_(file_op) {
  assert(storage_depth_ >= 0);
  CreateMissingDirectory(storage_dir_);
  CreateMissingDirectory(tmp_dir_);
}

FileStorage::~FileStorage() {
  delete file_op_;
}

std::set<bstring> FileStorage::Scan() const {
  std::set<bstring> storage_keys;
  ScanDir(storage_dir_, storage_depth_, &storage_keys);
  return storage_keys;
}

FileStorage::FileStorageResult
FileStorage::CreateEntry(const bstring &key, const bstring &data) {
  if (LookupEntry(key, NULL) == OK)
    return ENTRY_ALREADY_EXISTS;
  WriteStorageEntry(key, data);
  return OK;
}

FileStorage::FileStorageResult
FileStorage::UpdateEntry(const bstring &key, const bstring &data) {
  if (LookupEntry(key, NULL) != OK)
    return NOT_FOUND;
  WriteStorageEntry(key, data);
  return OK;
}

FileStorage::FileStorageResult
FileStorage::LookupEntry(const bstring &key, bstring *result) const {
  std::string data_file = StoragePath(key);
  if (!FileExists(data_file))
    return NOT_FOUND;
  if (result != NULL && !util::ReadBinaryFile(data_file, result))
    abort();
  return OK;
}

std::string FileStorage::StoragePathBasename(const std::string &hex) const {
  if (hex.length() <= storage_depth_)
    return "-";
  return hex.substr(storage_depth_);
}

std::string
FileStorage::StoragePathComponent(const std::string &hex, unsigned n) const {
  assert(n < storage_depth_);
  if (n >= hex.length())
    return "-";
  return std::string(1, hex[n]);
}

std::string FileStorage::StoragePath(const bstring &key) const {
  std::string hex = util::HexString(key);
  std::string dirname = storage_dir_ + "/";
  for (unsigned n = 0; n < storage_depth_; ++n)
    dirname += StoragePathComponent(hex, n) + "/";
  return dirname + StoragePathBasename(hex);
}

bstring FileStorage::StorageKey(const std::string &storage_path) const {
  assert(storage_path.substr(0, storage_dir_.size()) == storage_dir_);
  std::string key_path = storage_path.substr(storage_dir_.size() + 1);
  std::string hex_key;
  for (unsigned n = 0; n < storage_depth_; ++n) {
    char hex_char = key_path[2*n];
    if (hex_char == '-')
      return util::BinaryString(hex_key);
    hex_key.push_back(hex_char);
  }
  std::string basename = key_path.substr(2*storage_depth_);
  if (basename != "-")
    hex_key.append(basename);
  return util::BinaryString(hex_key);
}

void FileStorage::WriteStorageEntry(const bstring &key, const bstring &data) {
  std::string hex = util::HexString(key);

  // Make the intermediate directories, if needed.
  // TODO(ekasper): we can skip this if we know we're updating.
  std::string dir = storage_dir_;
  for (unsigned n = 0; n < storage_depth_; ++n) {
    dir += "/" + StoragePathComponent(hex, n);
    CreateMissingDirectory(dir);
  }

  // == StoragePath(key)
  std::string filename = dir + "/" + StoragePathBasename(hex);
  AtomicWriteBinaryFile(filename, data);
}

void FileStorage::ScanFiles(const std::string &dir_path,
                            std::set<bstring> *keys) const {
  DIR *dir = opendir(dir_path.c_str());
  if (dir == NULL)
    abort();
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_name[0] == '.')
      continue;
    keys->insert(StorageKey(dir_path + "/" + entry->d_name));
  }
  closedir(dir);
}

void FileStorage::ScanDir(const std::string &dir_path,
                          unsigned depth, std::set<bstring> *keys) const {
  if (depth > 0) {
    // Parse subdirectories. (TODO: make opendir part of filesystemop).
    DIR *dir = opendir(dir_path.c_str());
    if (dir == NULL)
      abort();
    struct dirent *entry;
    std::set<std::string> result;
    while ((entry = readdir(dir)) != NULL) {
      if (entry->d_name[0] == '.')
        continue;
      ScanDir(dir_path + "/" + entry->d_name, depth - 1, keys);
    }
    closedir(dir);
  } else {
    // depth == 0; parse files.
    ScanFiles(dir_path, keys);
  }
}

bool FileStorage::FileExists(const std::string &file_path) const {
  if (file_op_->access(file_path.c_str(), F_OK) == 0)
    return true;
  if (errno == ENOENT)
    return false;
  // Filesystem error.
  abort();
}

void FileStorage::AtomicWriteBinaryFile(const std::string &file_path,
                                        const bstring &data) {
  std::string tmp_file =
      util::WriteTemporaryBinaryFile(tmp_file_template_, data);
  if (tmp_file.empty() ||
      file_op_->rename(tmp_file.c_str(), file_path.c_str()) != 0)
    abort();
}

void FileStorage::CreateMissingDirectory(const std::string &dir_path) {
  if (file_op_->mkdir(dir_path.c_str(), 0700) != 0 && errno != EEXIST)
    abort();
}
