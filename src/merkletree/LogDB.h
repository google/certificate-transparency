// -*- mode: c++; indent-tabs-mode: nil; -*-

#ifndef LOGDB_H
#define LOGDB_H

#include <assert.h>
#include <map>
#include <set>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "../include/types.h"

class LogDB {
 public:
  virtual ~LogDB() {}

  enum Status {
    NOT_FOUND,
    REJECTED,
    NEW,
    PENDING,
    LOGGED
  };

  enum Lookup {
    ANY, // Logged and pending entries
    PENDING_ONLY, // Pending entries only
    LOGGED_ONLY, // Logged entries only
  };

  // Return the number of pending entries.
  virtual size_t PendingLogSize() const = 0;

  // Number of finished segments.
  virtual size_t SegmentCount() const = 0;

  // Add an entry to the pending bag of entries if it doesn't already exist.
  // The entry will be considered pending until the segment info is logged.
  // Returns NEW if the entry did not previously exist.
  // Returns PENDING or LOGGED if the entry already existed.
  virtual Status WriteEntry(const bstring &key, const bstring &data) = 0;

  // Construct a new segment from pending entries. Fix the order of entries,
  // and lock the segment, so that it can no longer be modified.
  // The segment will be written when WriteSegmentAndInfo() is called.
  // This should not be called again until the segment is written, i.e.,
  // the database can only have one pending segment at a time, and cannot
  // create new segments while a segment is pending.
  // Entries in this segment are considered as pending, but can also be read
  // sequentially via PendingSegmentEntry calls.
  virtual void MakeSegment() = 0;

  virtual bool HasPendingSegment() const = 0;

  virtual size_t PendingSegmentNumber() const = 0;

  virtual size_t PendingSegmentSize() const = 0;

  virtual Status PendingSegmentEntry(size_t index, bstring *data) const = 0;

  // Finalize the pending segment and info.
  virtual void WriteSegmentAndInfo(const bstring &info) = 0;

  // Retrieve the status of a log entry by absolute index. Indexing starts at 0.
  // Fill in |result| if it matches the |type| and |result| is not NULL.
  //  virtual Status LookupEntry(size_t index, Lookup type,
  //                             std::string *result) const = 0;

  // Retrieve a log entry by index in segment. Indexing starts at 0.
  // Fill in |result| if it matches the |type| and |result| is not NULL.
  virtual Status LookupEntry(size_t segment, size_t index,
                             bstring *result) const = 0;

  // Retrieve a log entry by its key.
  // Fill in |result| if it matches the |type| and |result| is not NULL.
  virtual Status LookupEntry(const bstring &key, Lookup type,
                             bstring *result) const = 0;

  // Retrieve the location of an entry by key.
  virtual Status EntryLocation(const bstring &key, size_t *segment,
                               size_t *index) const = 0;

  // Retrieve segment info. Indexing starts at 0.
  // Writes the segment info record if result is not NULL.
  virtual Status LookupSegmentInfo(size_t index, bstring *result) const = 0;
};

// A dumb memory-only logger.
class MemoryDB : public LogDB {
 public:
  MemoryDB();

  size_t PendingLogSize() const {
    return pending_.size();
  }

  size_t SegmentCount() const {
    return segment_infos_.size();
  }

  Status WriteEntry(const bstring &key, const bstring &data);

  void MakeSegment();

  bool HasPendingSegment() const { return has_pending_segment_; }

  size_t PendingSegmentNumber() const;

  size_t PendingSegmentSize() const;

  Status PendingSegmentEntry(size_t index, bstring *data) const;

  void WriteSegmentAndInfo(const bstring &data);

  Status LookupEntry(size_t segment, size_t index, bstring *result) const;

  Status LookupEntry(const bstring &key, Lookup type, bstring *result) const;

  Status EntryLocation(const bstring &key, size_t *segment,
                       size_t *index) const;

  Status LookupSegmentInfo(size_t index, bstring *result) const;

 private:
  Status LookupEntry(size_t index, Lookup type, bstring *result) const;

  // (segment, index_in_segment), counting from 0.
  struct Location {
    Location(size_t s, size_t i) : segment_number(s),
                                   index_in_segment(i) {}

    size_t segment_number;
    size_t index_in_segment;
  };
  // <key, data>
  typedef std::map<bstring, bstring> DataMap;
  // <<key>, <segment, index>>
  typedef std::map<bstring, Location> LocationMap;

  typedef std::set<bstring> KeySet;

  // All <key, data> entries.
  DataMap map_;
  // Pending keys.
  KeySet pending_;
  // Pending segment keys, ordered. These keys are also still in the
  // pending set.
  std::vector<bstring> pending_segment_;
  // Logged keys, ordered.
  std::vector<std::vector<bstring> > logged_;
  // Location map key -> location for logged entries.
  LocationMap logged_map_;

  std::vector<bstring> segment_infos_;

  bool has_pending_segment_;
};

/*
 * FileDB uses a simple filesystem-based store, structured as follows:
 *
 * <root>/storage - Storage for the certificate data, filenames are
 *                  derived from the key like so: "123456" becomes
 *                  "1/2/3/456". This is because filesystems tend to
 *                  perform badly with very large directories. Each
 *                  key has a directory containing files for the key
 *                  (in case of filename corruption or other such
 *                  difficulties), the data and the location of the
 *                  data in the tree. Writes to these files must be
 *                  atomic (i.e. create a new file and move into
 *                  place).
 *
 * <root>/tmp     - Temporary storage for atomicity. Must be on the
 *                  same filesystem as <root>/storage and
 *                  <root>/segments.
 *
 * <root>/pending - New certs are stored here until they are committed
 *                  to a segment. Each entry is a softlink from the
 *                  hex of the key to the key entry in <root>/storage.
 *
 * <root>/segments - Each segment has a directory whose name is the
 *                   segment number in decimal. Under each segment
 *                   directory is a softlink per cert, again numbered
 *                   in decimal.
 *
 * Updates are made semi-atomic by staging them in tmp. However, it is
 * not possible to make them truly atomic, so at startup it is
 * probably a good idea to retrieve any entries in tmp and move them
 * back to pending (after a check that they are not already logged?
 * shouldn't happen, but might be safer).
 */

class FileDB : public LogDB {
 public:
  FileDB(const std::string &file_base, unsigned storage_depth);
  // This class requires explicit initialization.
  void Init();

  size_t PendingLogSize() const;
  size_t SegmentCount() const;
  Status WriteEntry(const bstring &key, const bstring &data);
  void MakeSegment();
  bool HasPendingSegment() const;
  size_t PendingSegmentNumber() const;
  size_t PendingSegmentSize() const;
  Status PendingSegmentEntry(size_t index, bstring *data) const;
  void WriteSegmentAndInfo(const bstring &info);

  Status LookupEntry(size_t segment, size_t index, bstring *result) const;
  Status LookupEntry(const bstring &key, Lookup type, bstring *result) const;
  Status EntryLocation(const bstring &key, size_t *segment,
                       size_t *index) const;

  Status LookupSegmentInfo(size_t index, bstring *result) const;

 private:
  void ReadFile(const std::string &file, bstring *result) const;
  // Atomic: writes a tmp file and moves to place.
  void WriteFile(const std::string &filename, const bstring &data);
  // The last part of the storage directory.
  std::string StorageDirectoryBasename(const std::string &hex) const;
  // The names of intermediate directories.
  std::string StorageComponent(const std::string &hex, unsigned n) const;
  std::string StorageDirectory(const bstring &key) const;
  void CreateStorageEntry(const bstring &key, const bstring &data);
  void AddToPending(const bstring &key);
  bool IsPending(const bstring &key);
  bool IsQueuedForLogging(const bstring &key);
  bool IsLogged(const bstring &key);
  unsigned CountDirectory(const std::string &dir_name) const;

  // Create missing directories. Called by constructor.
  void MakeDirectories();
  // True if we have any temporarily locked data.
  bool HasTmpLockedData() const;
  // Constructing a segment did not complete; move locked entries back to pending.
  void UnlockTmp();
  // True if the pending segment directory contains a segment_info file.
  bool HasPendingSegmentInfo() const;
  void WritePendingSegment();

  // Called by Init(): completes or undoes any pending operations.
  void Heal();

  // Count the segments.
  size_t CountSegments() const;

  // Read the pending segment count from a file.
  size_t ReadPendingSegmentCount() const;

  // Convert a number to a decimal-base string.
  std::string ToString(size_t number) const;

  // Make file operations virtual, so we can override in a test class
  // and simulate their failure.
  virtual int mkdir(const char *path, mode_t mode);

  virtual int remove(const char *path);

  virtual int rename(const char *old_name, const char *new_name);

  const std::string kFileBase;
  // This directory only exists while we have a segment locked,
  // and are waiting for the segment info.
  const std::string kPendingSegmentDir;
  const std::string kPendingDir;
  const std::string kSegmentsDir;
  const std::string kStorageDir;
  // Scrapbook for atomic writes.
  const std::string kTmpDir;

  const unsigned storage_depth_;
  static const char kKeyFile[];
  static const char kDataFile[];
  static const char kInfoFile[];  // This file will only be present if
                                  // the data has been logged in a
                                  // completed segment.
  static const char kLockFile[];
  static const char kCountFile[];
  size_t segment_count_;
  size_t pending_segment_size_;
};

#endif  // ndef LOGDB_H
