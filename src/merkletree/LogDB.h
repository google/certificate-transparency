// -*- mode: c++; indent-tabs-mode: nil; -*-

#ifndef LOGDB_H
#define LOGDB_H

#include <map>
#include <string>
#include <vector>

#include <assert.h>

class LogDB {
 public:
  LogDB() {}
  virtual ~LogDB() {}

  enum Status {
    NOT_FOUND,
    NEW,
    PENDING,
    LOGGED
  };

  enum Lookup {
    ANY, // Logged and pending entries
    PENDING_ONLY, // Pending entries only
    LOGGED_ONLY, // Logged entries only
  };

  // Return the number of logged or pending entries.
  virtual size_t PendingLogSize() const = 0;
  //virtual size_t LoggedLogSize() const = 0;

  // Number of finished segments.
  virtual size_t SegmentCount() const = 0;

  // Append an entry to the pending segment if it doesn't already exist.
  // The entry will be considered pending until the segment info is logged.
  // Returns NEW if the entry did not previously exist.
  // Returns PENDING or LOGGED if the entry already existed.
  virtual Status WriteEntry(const std::string &key,
                            const std::string &data) = 0;

  // Move all currently pending data to a new segment, and add |data|
  // as the info. FIXME: rename to WriteNewSegmentAndInfo()?
  virtual void WriteSegmentInfo(const std::string &data) = 0;

  // Retrieve the status of a log entry by absolute index. Indexing starts at 0.
  // Fill in |result| if it matches the |type| and |result| is not NULL.
  //  virtual Status LookupEntry(size_t index, Lookup type,
  //                             std::string *result) const = 0;

  // Retrieve a log entry by index in segment. Indexing starts at 0.
  // Fill in |result| if it matches the |type| and |result| is not NULL.
  virtual Status LookupEntry(size_t segment, size_t index, Lookup type,
                             std::string *result) const = 0;

  // Retrieve a log entry by its key.
  // Fill in |result| if it matches the |type| and |result| is not NULL.
  virtual Status LookupEntry(const std::string &key, Lookup type,
                             std::string *result) const = 0;

  // Retrieve the location of an entry by key.
  virtual Status EntryLocation(const std::string &key, size_t *segment,
                               size_t *index) const = 0;

  // Retrieve segment info. Indexing starts at 0.
  // Writes the segment info record if result is not NULL.
  virtual Status LookupSegmentInfo(size_t index, std::string *result) const = 0;
};

// A dumb memory-only logger.
class MemoryDB : public LogDB {
 public:
  MemoryDB();

  size_t PendingLogSize() const {
    return entries_.size() - segment_offsets_.back();
  }

  size_t LoggedLogSize() const {
    return segment_offsets_.back();
  }

  size_t SegmentCount() const {
    return segment_infos_.size();
  }

  Status WriteEntry(const std::string &key, const std::string &data);

  void WriteSegmentInfo(const std::string &data);

  Status LookupEntry(size_t segment, size_t index, Lookup type,
                     std::string *result) const;

  Status LookupEntry(const std::string &key, Lookup type,
                     std::string *result) const;

  Status EntryLocation(const std::string &key, size_t *segment,
                       size_t *index) const;

  Status LookupSegmentInfo(size_t index, std::string *result) const;

 private:
  Status LookupEntry(size_t index, Lookup type, std::string *result) const;

  std::vector<std::string> entries_;
  std::vector<size_t> segment_offsets_;
  std::vector<std::string> segment_infos_;

  // (segment, index_in_segment), counting from 0.
  struct Location {
    Location(size_t s, size_t i) : segment_number(s),
                                   index_in_segment(i) {}

    size_t segment_number;
    size_t index_in_segment;
  };
  typedef std::map<std::string, Location> LocationMap;
  // Map the key to the location.
  LocationMap map_;
};

std::string HexString(const std::string &data);

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
  FileDB(const std::string &file_base, unsigned storage_depth)
    : file_base_(file_base), storage_depth_(storage_depth) {
  }

  size_t PendingLogSize() const;
  size_t SegmentCount() const;
  Status WriteEntry(const std::string &key, const std::string &data);
  void WriteSegmentInfo(const std::string &data);
  Status LookupEntry(size_t segment, size_t index, Lookup type,
                     std::string *result) const;
  Status LookupEntry(const std::string &key, Lookup type,
                     std::string *result) const;
  Status EntryLocation(const std::string &key, size_t *segment,
                       size_t *index) const {
    assert(false);
  }
  Status LookupSegmentInfo(size_t index, std::string *result) const;

 private:
  void ReadFile(const std::string &file, std::string *result) const;
  void WriteFile(const std::string &filename, const std::string &data);
  // The last part of the storage directory.
  std::string StorageDirectoryBasename(const std::string &hex) const;
  // The names of intermediate directories.
  std::string StorageComponent(const std::string &hex, unsigned n) const;
  std::string StorageDirectory(const std::string &key) const;
  void CreateStorageEntry(const std::string &key, const std::string &data);
  void AddToPending(const std::string &key);
  unsigned CountDirectory(const std::string &dir_name) const;

  const std::string file_base_;
  const unsigned storage_depth_;
  static const char kKeyFile[];
  static const char kDataFile[];
  static const char kInfoFile[];  // This file will only be present if
                                  // the data has been logged in a
                                  // completed segment.
};

#endif  // ndef LOGDB_H
