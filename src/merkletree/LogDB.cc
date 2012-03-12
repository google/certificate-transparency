#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/stat.h>

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

MemoryDB::MemoryDB() {
  segment_offsets_.push_back(0);
}

LogDB::Status MemoryDB::WriteEntry(const std::string &key,
                                   const std::string &data) {
  // Check for duplicates.
  Location loc(segment_infos_.size(),
               entries_.size() - segment_offsets_.back());
  // LocationMap is a map of (key, Location) pairs.
  std::pair<LocationMap::iterator, bool> inserted =
      map_.insert(LocationMap::value_type(key, loc));
  if (inserted.second) {
    entries_.push_back(data);
    return LogDB::NEW;
  }
  if (inserted.first->second.segment_number == segment_infos_.size())
    return LogDB::PENDING;
  assert(inserted.first->second.segment_number < segment_infos_.size());
  return LogDB::LOGGED;
}

void MemoryDB::WriteSegmentInfo(const std::string &data) {
  segment_offsets_.push_back(entries_.size());
  segment_infos_.push_back(data);
}

LogDB::Status MemoryDB::LookupEntry(size_t index, LogDB::Lookup type,
                                    std::string *result) const {
  if (index >= entries_.size())
    return LogDB::NOT_FOUND;

  if (index >= segment_offsets_.back()) {
    if (result != NULL && (type == LogDB::ANY || type == LogDB::PENDING_ONLY))
      result->assign(entries_[index]);
    return LogDB::PENDING;
  }
  if (result != NULL && (type == LogDB::ANY || type == LogDB::LOGGED_ONLY))
    result->assign(entries_[index]);
  return LogDB::LOGGED;
}

LogDB::Status MemoryDB::LookupEntry(size_t segment, size_t index,
                                    LogDB::Lookup type,
                                    std::string *result) const {
  if (segment >= segment_offsets_.size())
    return LogDB::NOT_FOUND;
  size_t loc = segment_offsets_[segment] + index;
  return LookupEntry(loc, type, result);
}

LogDB::Status MemoryDB::LookupEntry(const std::string &key, LogDB::Lookup type,
                                    std::string *result) const {
  LocationMap::const_iterator it = map_.find(key);
  if (it == map_.end())
    return LogDB::NOT_FOUND;
  return LookupEntry(it->second.segment_number, it->second.index_in_segment,
                     type, result);
}

LogDB::Status MemoryDB::EntryLocation(const std::string &key, size_t *segment,
                                      size_t *index) const {
  LocationMap::const_iterator it = map_.find(key);
  if (it == map_.end())
    return LogDB::NOT_FOUND;
  assert(segment != NULL && index != NULL);
  *segment = it->second.segment_number;
  *index = it->second.index_in_segment;
  if (*segment == segment_infos_.size())
    return LogDB::PENDING;
  assert(*segment < segment_infos_.size());
  return LogDB::LOGGED;
}

LogDB::Status MemoryDB::LookupSegmentInfo(size_t index,
                                          std::string *result) const {
  if (index > segment_infos_.size())
    return LogDB::NOT_FOUND;
  if (index == segment_infos_.size())
    return LogDB::PENDING;
  if (result != NULL)
    result->assign(segment_infos_[index]);
  return LogDB::LOGGED;
}

const char FileDB::kKeyFile[] = "key";
const char FileDB::kDataFile[] = "data";
const char FileDB::kInfoFile[] = "info";

size_t FileDB::PendingLogSize() const {
  return CountDirectory(file_base_ + "/pending");
}

size_t FileDB::SegmentCount() const {
  return CountDirectory(file_base_ + "/segments");
}

LogDB::Status FileDB::WriteEntry(const std::string &key,
				 const std::string &data) {
  std::string dir = StorageDirectory(key);
  // kDataFile must be created last in a pending entry.
  if (access((dir + "/" + kDataFile).c_str(), O_RDONLY) < 0) {
    std::cout << "dir is " << dir << " errno " << errno << std::endl;
    assert(errno == ENOENT);
    CreateStorageEntry(key, data);
    AddToPending(key);
    return LogDB::NEW;
  }

  if (access((dir + "/" + kInfoFile).c_str(), O_RDONLY) < 0) {
    assert(errno == ENOENT);
    // in case the storage was created but not the pending entry.
    AddToPending(key);
    return LogDB::PENDING;
  }
  return LogDB::LOGGED;
}

void FileDB::WriteSegmentInfo(const std::string &data) {
  size_t next_segment = SegmentCount();
  char buf[100];
  sprintf(buf, "%d", next_segment);
  std::string segment_number(buf);
  std::string tmp_dir(file_base_ + "/tmp/" + segment_number);
  int ret = mkdir(tmp_dir.c_str(), 0777);
  assert(ret >= 0);
  std::string pending = file_base_ + "/pending";
  DIR *dir = opendir(pending.c_str());
  assert(dir);
  unsigned count = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_name[0] == '.')
      continue;
    sprintf(buf, "/%d", count++);
    std::string from(pending + "/" + entry->d_name);
    std::string to(tmp_dir + buf);
    std::cout << "Move " << from << " to " << to << std::endl;
    ret = rename(from.c_str(), to.c_str());
    assert(ret >= 0);
    std::string info(segment_number + buf);
    WriteFile(to + "/info", info);
    // I'm not sure if this is needed or effective, but seems
    // wise...
    rewinddir(dir);
  }
  closedir(dir);
  WriteFile(tmp_dir + "/segment_info", data);

  // Finally, move into place.
  std::string segment_dir(file_base_ + "/segments/" + segment_number);
  ret = rename(tmp_dir.c_str(), segment_dir.c_str());
  assert( ret >= 0);
}

LogDB::Status FileDB::LookupEntry(size_t segment, size_t index, Lookup type,
				  std::string *result) const {
  char buf[100];
  sprintf(buf, "%d/%d", segment, index);
  std::string dirname(file_base_ + "/segments/" + buf);
  if (access(dirname.c_str(), O_RDONLY) < 0)
    return NOT_FOUND;
  ReadFile(dirname + "/data", result);
  return LOGGED;
}

LogDB::Status FileDB::LookupEntry(const std::string &key, Lookup type,
				  std::string *result) const {
  std::string dir = StorageDirectory(key);
  Status ret = PENDING;
  std::string data_file(dir + "/" + kDataFile);
  if (access((dir + "/" + kInfoFile).c_str(), O_RDONLY) >= 0)
    ret = LOGGED;
  else if (access(data_file.c_str(), O_RDONLY) < 0)
    return NOT_FOUND;
  // FIXME: I suspect this logic should be in the parent class?
  if (type == PENDING_ONLY && ret != PENDING)
    return ret;
  if (type == LOGGED_ONLY && ret != LOGGED)
    return ret;

  if (result)
    ReadFile(data_file, result);
  
  return ret;
}

LogDB::Status FileDB::LookupSegmentInfo(size_t index, std::string *result)
  const {
  char buf[100];

  sprintf(buf, "%d", index);
  std::string info(file_base_ + "/segments/" + buf + "/segment_info");
  if (access(info.c_str(), O_RDONLY) < 0)
    return NOT_FOUND;
  ReadFile(info, result);
  return LOGGED;
}

void FileDB::ReadFile(const std::string &file, std::string *result) const {
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
  std::ofstream file(filename.c_str(), std::ios::out | std::ios::trunc);
  assert(file.good());
  file.write(data.data(), data.length());
  assert(file.good());
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
  std::string dirname = file_base_ + "/storage/";
  for (unsigned n = 0; n < storage_depth_; ++n)
    dirname += StorageComponent(hex, n) + "/";
  return dirname + StorageDirectoryBasename(hex);
}

void FileDB::CreateStorageEntry(const std::string &key,
				const std::string &data) {
  std::string hex = HexString(key);
  std::string dir = StorageDirectoryBasename(hex);
  std::string tmpdir = file_base_ + "/tmp/" + dir;

  // Create temporary directory
  int ret = mkdir(tmpdir.c_str(), 0777);
  assert(ret >= 0 || errno == EEXIST);

  WriteFile(tmpdir + "/" + kKeyFile, key);
  WriteFile(tmpdir + "/" + kDataFile, data);

  // Make the intermediate directories, if needed.
  dir = file_base_ + "/storage";
  for (unsigned n = 0; n < storage_depth_; ++n) {
    dir += "/" + StorageComponent(hex, n);
    std::cout << "Making " << dir << std::endl;
    ret = mkdir(dir.c_str(), 0777);
    assert(ret >= 0 || errno == EEXIST);
  }

  std::string dest = StorageDirectory(key);
  std::cout << "Moving " << tmpdir << " to " << dest << std::endl;
  ret = rename(tmpdir.c_str(), dest.c_str());
  assert(ret >= 0);
}

void FileDB::AddToPending(const std::string &key) {
  std::string pending = file_base_ + "/pending/" + HexString(key);
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
