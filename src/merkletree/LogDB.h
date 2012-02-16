#ifndef LOGDB_H
#define LOGDB_H
#include <map>
#include <string>
#include <vector>

#include <stddef.h>

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

  // Return the number of logged/pending or logged and pending entries,
  // depending on the Lookup type.
  virtual size_t LogSize(Lookup type) const = 0;

  // Number of finished segments.
  virtual size_t SegmentCount() const = 0;

  // Append an entry to the pending segment if it doesn't already exist.
  // The entry will be considered pending until the segment info is logged.
  // Returns NEW if the entry did not previously exist.
  // Returns PENDING or LOGGED if the entry already existed.
  virtual Status WriteEntry(const std::string &key,
                            const std::string &data) = 0;

  // Write the segment info, and start a new segment.
  virtual void WriteSegmentInfo(const std::string &data) = 0;

  // Retrieve the status of a log entry by absolute index. Indexing starts at 0.
  // Write the data record if it matches the Lookup type and result is not NULL.
  virtual Status LookupEntry(size_t index, Lookup type,
                             std::string *result) const = 0;

  // Retrieve a log entry by index in segment. Indexing starts at 0.
  // Write the data record if it matches the Lookup type and result is not NULL.
  virtual Status LookupEntry(size_t segment, size_t index, Lookup type,
                             std::string *result) const = 0;

  // Retrieve a log entry by its key.
  // Write the data record if it matches the Lookup type and result is not NULL.
  virtual Status LookupEntry(const std::string &key, Lookup type,
                             std::string *result) const = 0;

  // Retrieve segment info. Indexing starts at 0.
  // Writes the segment info record if result is not NULL.
  virtual Status LookupSegmentInfo(size_t index, std::string *result) const = 0;
};

// A dumb memory-only logger.
class MemoryDB : public LogDB {
 public:
  MemoryDB();

  size_t LogSize(Lookup type) const {
    switch (type) {
      case LogDB::ANY:
        return entries_.size();
      case LogDB::PENDING_ONLY:
        return entries_.size() - segment_offsets_.back();
      case LogDB::LOGGED_ONLY:
        return segment_offsets_.back();
      default:
        assert(false);
    }
  }

  size_t SegmentCount() const {
    return segment_infos_.size();
  }

  Status WriteEntry(const std::string &key, const std::string &data);

  void WriteSegmentInfo(const std::string &data);

  Status LookupEntry(size_t index, Lookup type, std::string *result) const;

  Status LookupEntry(size_t segment, size_t index, Lookup type,
                     std::string *result) const;

  Status LookupEntry(const std::string &key, Lookup type,
                     std::string *result) const;

  Status LookupSegmentInfo(size_t index, std::string *result) const;

 private:
  std::vector<std::string> entries_;
  std::vector<size_t> segment_offsets_;
  std::vector<std::string> segment_infos_;

  typedef std::map<std::string,size_t> index;
  // Map the key to the location.
  index index_;
};
#endif
