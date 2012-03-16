#include <fstream>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../util/util.h"
#include "LogDB.h"

static const char *nibble = "0123456789abcdef";

std::string HexString(const std::string &data) {
  if (data.empty())
    return "-";
  std::string ret;
  for (unsigned int i = 0; i < data.size(); ++i) {
    ret.push_back(nibble[(data[i] >> 4) & 0xf]);
    ret.push_back(nibble[data[i] & 0xf]);
  }
  return ret;
}

MemoryDB::MemoryDB() : has_pending_segment_(false) {}

LogDB::Status MemoryDB::WriteEntry(const std::string &key,
                                   const std::string &data) {
  // Try to insert.
  std::pair<DataMap::iterator, bool> inserted =
      map_.insert(DataMap::value_type(key, data));
  if (inserted.second) {
    pending_.insert(key);
    return NEW;
  } else {
    LocationMap::const_iterator it = logged_map_.find(key);
    if (it != logged_map_.end())
      return LOGGED;
    return PENDING;
  }
}

void MemoryDB::MakeSegment() {
  if (HasPendingSegment())
    return;
  assert(pending_segment_.empty());
  KeySet::const_iterator it;
  // Fix the order of pending entries in the segment.
  for (it = pending_.begin(); it != pending_.end(); ++it)
    pending_segment_.push_back(*it);
  has_pending_segment_ = true;
}

size_t MemoryDB::PendingSegmentNumber() const {
  assert(HasPendingSegment());
  return SegmentCount();
}

size_t MemoryDB::PendingSegmentSize() const {
  assert(HasPendingSegment());
  return pending_segment_.size();
}

LogDB::Status
MemoryDB::PendingSegmentEntry(size_t index, std::string *data) const {
  assert(HasPendingSegment());
  if (index >= pending_segment_.size())
    return NOT_FOUND;
  DataMap::const_iterator it = map_.find(pending_segment_[index]);
  assert(it != map_.end());
  data->assign(it->second);
  return PENDING;
}

void MemoryDB::WriteSegmentAndInfo(const std::string &data) {
  // Remove the keys from the pending bag.
  size_t segment = PendingSegmentNumber();
  for (size_t index = 0; index < pending_segment_.size(); ++index) {
    Location loc(segment, index);
    std::string key = pending_segment_[index];
    logged_map_.insert(LocationMap::value_type(key, loc));
    pending_.erase(key);
  }
  logged_.push_back(pending_segment_);
  pending_segment_.clear();
  segment_infos_.push_back(data);
  has_pending_segment_ = false;
}

LogDB::Status MemoryDB::LookupEntry(size_t segment, size_t index,
                                    std::string *result) const {
  if (segment >= logged_.size() || index >= logged_[segment].size())
    return NOT_FOUND;
  if (result) {
    const std::string key = logged_[segment][index];
    DataMap::const_iterator it = map_.find(key);
    assert(it != map_.end());
    result->assign(it->second);
  }
  return LOGGED;
}

LogDB::Status MemoryDB::LookupEntry(const std::string &key, LogDB::Lookup type,
                                    std::string *result) const {
  DataMap::const_iterator data_it = map_.find(key);
  if (data_it == map_.end())
    return NOT_FOUND;
  LocationMap::const_iterator log_it = logged_map_.find(key);
  Status ret;
  if (log_it != logged_map_.end())
    ret = LOGGED;
  else
    ret = PENDING;

  // FIXME: I suspect this logic should be in the parent class?
  if (type == PENDING_ONLY && ret != PENDING)
    return ret;
  if (type == LOGGED_ONLY && ret != LOGGED)
    return ret;

  if (result)
    result->assign(data_it->second);
  return ret;
}

LogDB::Status MemoryDB::EntryLocation(const std::string &key, size_t *segment,
                                      size_t *index) const {
  LocationMap::const_iterator it = logged_map_.find(key);
  if (it == logged_map_.end())
    return NOT_FOUND;
  assert(segment != NULL && index != NULL);
  *segment = it->second.segment_number;
  *index = it->second.index_in_segment;
  return LogDB::LOGGED;
}

LogDB::Status MemoryDB::LookupSegmentInfo(size_t index,
                                          std::string *result) const {
  if (index >= segment_infos_.size())
    return LogDB::NOT_FOUND;
  if (result != NULL)
    result->assign(segment_infos_[index]);
  return LogDB::LOGGED;
}

const char FileDB::kKeyFile[] = "key";
const char FileDB::kDataFile[] = "data";
const char FileDB::kInfoFile[] = "info";
const char FileDB::kLockFile[] = "lock";
const char FileDB::kCountFile[] = "count";

FileDB::FileDB(const std::string &file_base, unsigned storage_depth)
    : kFileBase(file_base),
      kPendingSegmentDir(file_base + "/lock"),
      kPendingDir(file_base + "/pending"),
      kSegmentsDir(file_base + "/segments"),
      kStorageDir(file_base + "/storage"),
      kTmpDir(file_base + "/tmp"),
      storage_depth_(storage_depth) {
  // Create missing directories.
  MakeDirectories();
  // Count segments.
  segment_count_ = CountSegments();
  if (HasPendingSegment())
    pending_segment_size_ = ReadPendingSegmentCount();

  // Heal locked data.
  Heal();
  assert(!HasTmpLockedData());
  assert(!HasPendingSegment() || !HasPendingSegmentInfo());
}

size_t FileDB::PendingLogSize() const {
  if (HasPendingSegment())
    return PendingSegmentSize() + CountDirectory(kPendingDir);
  else
    return CountDirectory(kPendingDir);
}

size_t FileDB::SegmentCount() const {
  return segment_count_;
}

LogDB::Status FileDB::WriteEntry(const std::string &key,
				 const std::string &data) {
  std::string dir = StorageDirectory(key);
  // kDataFile must be created last in a pending entry.
  if (access((dir + "/" + kDataFile).c_str(), R_OK) < 0) {
    assert(errno == ENOENT);
    CreateStorageEntry(key, data);
    AddToPending(key);
    return LogDB::NEW;
  }

  if (access((dir + "/" + kInfoFile).c_str(), R_OK) < 0) {
    assert(errno == ENOENT);
    // in case the storage was created but not the pending entry.
    if (access((dir + "/" + kLockFile).c_str(), R_OK) < 0) {
      assert(errno == ENOENT);
      AddToPending(key);
    }
    return LogDB::PENDING;
  }
  return LogDB::LOGGED;
}

// The steps for logging a segment are as follows:
// 1. Create a pending segment directory file_base/pending_segment
// 2. Move entries from file_base/pending to file_base/pending_segment.
//    The entries in pending are symlinks to the storage directory, with
//    the key as the name of the symlink. For example:
//    file_base/pending/987654 -> file_base/storage/9/8/7/654
//    file_base/pending/012345 -> file_base/storage/0/1/2/345
//    These now become symlinks in the pending segment directory, with
//    the sequence number as the name of the symlink:
//    file_base/pending_segment/0 -> file_base/storage/9/8/7/654
//    file_base/pending_segment/1 -> file_base/storage/0/1/2/345
//
//    Additionally, we write a lock file in the storage directory of each entry
//    to indicate that it has been queued for logging:
//    file_base/storage/9/8/7/654/lock
//    file_base/storage/0/1/2/345/lock
// 3. Write a count file in the pending segment directory to indicate
//    that the segment is complete and we are waiting for segment info:
//    file_base/pending_segment/count
//    (Logger can read the pending segment directory to produce the info.)
// 4. Wait for logger to send segment info.
// 5. Remove the lock files, write info files and move segment to destination:
//    write  file_base/pending_segment/segment_info
//    remove file_base/storage/9/8/7/654/lock
//    write  file_base/storage/9/8/7/654/info
//    move file_base/pending_segment to file_base/segments/
//    (e.g., the first pending segment becomes file_base/segments/0)
//
// Recovery steps upon boot:
// 1. There is a pending segment directory file_base/pending_segment
//    but no count file file_base/pending/segment/count - unlock everything
//    in the pending_segment and move back to pending (undo 1.-2.).
// 2. There is a pending segment directory and a count file, but no
//    file_base/pending_segment/segment_info: do nothing.
//    It is the logger's responsibility to sign the segment.
// 3. There is a pending segment directory, a count and a segment info file:
//    redo step 5.
void FileDB::MakeSegment() {
  if (HasPendingSegment())
    return;
  int ret = mkdir(kPendingSegmentDir.c_str(), 0777);
  assert(ret >= 0);
  DIR *dir = opendir(kPendingDir.c_str());
  assert(dir);
  unsigned count = 0;
  struct dirent *entry;
  std::string segment_bytestring = util::SerializeUint(segment_count_, 4);
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_name[0] == '.')
      continue;
    std::string from(kPendingDir + "/" + entry->d_name);
    std::string index_bytestring = util::SerializeUint(count, 4);
    std::string index = ToString(count++);
    std::string to(kPendingSegmentDir + "/" + index);
    ret = rename(from.c_str(), to.c_str());
    assert(ret >= 0);
    std::string info(segment_bytestring + index_bytestring);
    // Write a lock file to indicate that the entry is queued for logging
    // and we shouldn't try to add it back to the pending bag.
    // Include the entry info in the lock file, so in step 5, we can simply
    // rename lock to info.
    WriteFile(to + "/" + kLockFile, info);
    // I'm not sure if this is needed or effective, but seems
    // wise...
    rewinddir(dir);
  }
  std::string count_bytestring = util::SerializeUint(count, 4);
  closedir(dir);

  // Done; write the count. This commits the segment.
  pending_segment_size_ = count;
  WriteFile(kPendingSegmentDir + "/count", count_bytestring);
}

bool FileDB::HasPendingSegment() const {
  if (access(kPendingSegmentDir.c_str(), R_OK) < 0) {
    assert(errno == ENOENT);
    return false;
  }
  // A pending segment directory must have a count file.
  assert(access((kPendingSegmentDir + "/" + kCountFile).c_str(), R_OK) == 0);
  return true;
}

size_t FileDB::PendingSegmentNumber() const {
  assert(HasPendingSegment());
  return SegmentCount();
}

size_t FileDB::PendingSegmentSize() const {
  assert(HasPendingSegment());
  return pending_segment_size_;
}

LogDB::Status
FileDB::PendingSegmentEntry(size_t index, std::string *result) const {
  assert(HasPendingSegment());
  std::string entry_dir(kPendingSegmentDir + "/" + ToString(index));
  if (access(entry_dir.c_str(), R_OK) < 0) {
    assert(errno == ENOENT);
    return NOT_FOUND;
  }
  std::string data_file(entry_dir + "/" + kDataFile);
  assert(access(data_file.c_str(), R_OK) == 0);
  ReadFile(data_file, result);
  return PENDING;
}

void FileDB::WriteSegmentAndInfo(const std::string &info) {
  assert(HasPendingSegment());
  WriteFile(kPendingSegmentDir + "/segment_info", info);
  WritePendingSegment();
}

LogDB::Status FileDB::LookupEntry(size_t segment, size_t index,
                                  std::string *result) const {
  if (segment >= SegmentCount())
    return NOT_FOUND;
  std::string dirname(kSegmentsDir + "/" + ToString(segment) + "/" +
                      ToString(index));
  if (access(dirname.c_str(), R_OK) < 0)
    return NOT_FOUND;
  std::string data_file(dirname + "/" + kDataFile);
  if (result)
    ReadFile(data_file, result);
  return LOGGED;
}

LogDB::Status FileDB::LookupEntry(const std::string &key, Lookup type,
				  std::string *result) const {
  std::string dir = StorageDirectory(key);
  Status ret = PENDING;
  std::string data_file(dir + "/" + kDataFile);
  if (access((dir + "/" + kInfoFile).c_str(), R_OK) == 0)
    ret = LOGGED;
  else if (access(data_file.c_str(), R_OK) < 0) {
    assert(errno == ENOENT);
    return NOT_FOUND;
  }
  // FIXME: I suspect this logic should be in the parent class?
  if (type == PENDING_ONLY && ret != PENDING)
    return ret;
  if (type == LOGGED_ONLY && ret != LOGGED)
    return ret;

  if (result)
    ReadFile(data_file, result);

  return ret;
}

LogDB::Status FileDB::EntryLocation(const std::string &key, size_t *segment,
                                    size_t *index) const {
  std::string dir = StorageDirectory(key);
  std::string info_file(dir + "/" + kInfoFile);
  if (access(dir.c_str(), R_OK) < 0) {
    assert(errno == ENOENT);
    return NOT_FOUND;
  } else if (access(info_file.c_str(), R_OK) < 0) {
    assert(errno == ENOENT);
    return PENDING;
  } else {
    std::string info;
    ReadFile(info_file, &info);
    assert(info.size() == 8);
    *segment = util::DeserializeUint(info.substr(0, 4));
    *index = util::DeserializeUint(info.substr(4));
    return LOGGED;
  }
}

LogDB::Status FileDB::LookupSegmentInfo(size_t index, std::string *result)
  const {
  std::string info(kSegmentsDir + "/" + ToString(index) + "/segment_info");
  if (access(info.c_str(), R_OK) < 0) {
    assert(errno == ENOENT);
    return NOT_FOUND;
  }
  ReadFile(info, result);
  return LOGGED;
}

void FileDB::ReadFile(const std::string &file, std::string *result) const {
  assert(result != NULL);
  std::ifstream data(file.c_str());
  assert(data.good());
  // FIXME: do something better about reading all the data
  char buf[10240];
  data.read(buf, sizeof buf);
  std::streamsize count = data.gcount();
  assert(data.eof());
  assert(!data.bad());
  *result = std::string(buf, count);
}

void FileDB::WriteFile(const std::string &filename, const std::string &data) {
  std::string tmp_file(kTmpDir + "/tmp_file");
  std::ofstream file(tmp_file.c_str(), std::ios::out | std::ios::trunc);
  assert(file.good());
  file.write(data.data(), data.length());
  assert(file.good());
  file.close();
  assert(rename(tmp_file.c_str(), filename.c_str()) == 0);
}

std::string FileDB::StorageDirectoryBasename(const std::string &hex) const {
  if (hex.length() <= storage_depth_)
    return "-";
  return hex.substr(storage_depth_);
}

std::string FileDB::StorageComponent(const std::string &hex, unsigned n) const {
  assert(n < storage_depth_);
  if (n >= hex.length())
    return "-";
  return std::string(1, hex[n]);
}

std::string FileDB::StorageDirectory(const std::string &key) const {
  std::string hex = HexString(key);
  std::string dirname = kStorageDir + "/";
  for (unsigned n = 0; n < storage_depth_; ++n)
    dirname += StorageComponent(hex, n) + "/";
  return dirname + StorageDirectoryBasename(hex);
}

void FileDB::CreateStorageEntry(const std::string &key,
				const std::string &data) {
  std::string hex = HexString(key);
  std::string dir = StorageDirectoryBasename(hex);
  std::string tmpdir = kTmpDir + "/" + dir;

  // Create temporary directory
  int ret = mkdir(tmpdir.c_str(), 0777);
  assert(ret >= 0 || errno == EEXIST);

  WriteFile(tmpdir + "/" + kKeyFile, key);
  WriteFile(tmpdir + "/" + kDataFile, data);

  // Make the intermediate directories, if needed.
  dir = kStorageDir;
  for (unsigned n = 0; n < storage_depth_; ++n) {
    dir += "/" + StorageComponent(hex, n);
    ret = mkdir(dir.c_str(), 0777);
    assert(ret >= 0 || errno == EEXIST);
  }

  std::string dest = StorageDirectory(key);
  ret = rename(tmpdir.c_str(), dest.c_str());
  assert(ret >= 0);
}

void FileDB::AddToPending(const std::string &key) {
  std::string pending = kPendingDir + "/" + HexString(key);
  int ret = symlink(StorageDirectory(key).c_str(), pending.c_str());
  // FIXME: if EEXIST, then check the file is correct and fix if not.
  assert(ret >= 0 || errno == EEXIST);
}

unsigned FileDB::CountDirectory(const std::string &dir_name) const {
  DIR *dir = opendir(dir_name.c_str());
  assert(dir);
  unsigned count = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
    if (entry->d_name[0] != '.')
      ++count;
  closedir(dir);
  return count;
}

void FileDB::MakeDirectories() {
  if (access(kPendingDir.c_str(), W_OK) < 0) {
    assert(errno == ENOENT);
    assert(mkdir(kPendingDir.c_str(), 0777) >= 0);
  }

  if (access(kSegmentsDir.c_str(), W_OK) < 0) {
    assert(errno == ENOENT);
    assert(mkdir(kSegmentsDir.c_str(), 0777) >= 0);
  }

  if (access(kStorageDir.c_str(), W_OK) < 0) {
    assert(errno == ENOENT);
    assert(mkdir(kStorageDir.c_str(), 0777) >= 0);
  }

  if (access(kTmpDir.c_str(), W_OK) < 0) {
    assert(errno == ENOENT);
    assert(mkdir(kTmpDir.c_str(), 0777) >= 0);
  }
}

bool FileDB::HasTmpLockedData() const {
  if (access(kPendingSegmentDir.c_str(), R_OK) < 0) {
    assert(errno == ENOENT);
    return false;
  } else if (access((kPendingSegmentDir + "/" + kCountFile).c_str(),
                    R_OK) == 0) {
    return false;
  } else {
    assert(errno == ENOENT);
    // We have pending entries, but no count file, so we can't consider
    // this segment as complete.
    return true;
  }
}

void FileDB::UnlockTmp() {
  if (!HasTmpLockedData())
    return;

  DIR *dir = opendir(kPendingSegmentDir.c_str());
  assert(dir);
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_name[0] == '.')
      continue;
    std::string from(kPendingSegmentDir + "/" + entry->d_name);
    std::string key;
    ReadFile(from + "/" + kKeyFile, &key);
    AddToPending(key);
    std::string lock_file(from + "/" + kLockFile);
    if (access(lock_file.c_str(), W_OK) == 0)
      assert(remove(lock_file.c_str()) == 0);
    else
      assert(errno == ENOENT);
    assert(remove(from.c_str()) == 0);
    rewinddir(dir);
  }
  closedir(dir);
  assert(remove(kPendingSegmentDir.c_str()) == 0);
}

bool FileDB::HasPendingSegmentInfo() const {
  if (access((kPendingSegmentDir + "/segment_info").c_str(), R_OK) == 0)
    return true;
  assert(errno == ENOENT);
  return false;
}

void FileDB::WritePendingSegment() {
  assert(HasPendingSegment());
  assert(HasPendingSegmentInfo());

  // Count the directory again, just to be extra sure.
  size_t count = CountDirectory(kPendingSegmentDir);
  // The entries, plus segment_info and count.
  assert(count == pending_segment_size_ + 2);
  int ret;
  for (size_t index = 0; index < pending_segment_size_; ++index) {
    std::string entry_dir(kPendingSegmentDir + "/" + ToString(index));
    assert(access(entry_dir.c_str(), W_OK) == 0);
    std::string from(entry_dir + "/" + kLockFile);
    std::string to(entry_dir + "/" + kInfoFile);
    if (access(from.c_str(), R_OK) < 0) {
      // File does not exist. This can happen if the last
      // attempt failed after moving this file.
      assert(errno == ENOENT);
      assert(access(to.c_str(), R_OK) == 0);
      continue;
    }
    ret = rename(from.c_str(), to.c_str());
    assert(ret >= 0);
  }

  // Done writing info; move segment to place.
  // Keep the count file; it won't hurt.
  std::string segment_dir(kSegmentsDir + "/" + ToString(segment_count_));
  ret = rename(kPendingSegmentDir.c_str(), segment_dir.c_str());
  assert(ret >= 0);
  ++segment_count_;
  // Count again, just in case.
  assert(segment_count_ == CountSegments());
}

void FileDB::Heal() {
  // Heal locked data.
  if (HasTmpLockedData()) {
    // We have no master lock, but have locked data.
    // We failed befor completing the segment; undo.
    UnlockTmp();
  } else if (HasPendingSegment() && HasPendingSegmentInfo()) {
    // We already have the segment info so we must have failed
    // just before writing it; do so now.;
    WritePendingSegment();
  }
}

size_t FileDB::CountSegments() const {
  return CountDirectory(kSegmentsDir);
}

size_t FileDB::ReadPendingSegmentCount() const {
  std::string count;
  ReadFile(kPendingSegmentDir + "/count", &count);
  assert(count.size() == 4);
  return util::DeserializeUint(count);
}

std::string FileDB::ToString(size_t number) const {
  char buf[20];
  sprintf(buf, "%zu", number);
  return std::string(buf);
}
