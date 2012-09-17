#ifndef FILE_DB_H
#define FILE_DB_H

#include <set>
#include <stdint.h>
#include <string>

#include "types.h"

class FilesystemOp;

// A simple filesystem-based database for (key, data) entries,
// structured as follows:
//
// <root>/storage - Storage for the data, filenames are derived from the hex key
//                  like so: "89abcd" becomes "8/9/a/bcd" (for storage depth 3).
//                  This is because filesystems tend to perform badly with very
//                  large directories. For this to work, we assume keys are
//                  hashes, i.e., random, and of reasonable length.
//                  However, numerical monotonically increasing keys can be
//                  made to work too: for example, 4-byte keys could be set up
//                  with max 256 entries/directory by setting storage_depth=6:
//                  "00000000" -> "0/0/0/0/0/0/00"
//                  "00000001" -> "0/0/0/0/0/0/01"
//                  ...
//                  "00000100" -> "0/0/0/0/0/1/00"
//                  ...
//
//                  Each key corresponds to a file with the data.
//                  Writes to these files are atomic
//                  (i.e. create a new file and move into place).
//
// <root>/tmp     - Temporary storage for atomicity. Must be on the
//                  same filesystem as <root>/storage.

// FileDB aborts Upon any FilesystemOp error.
class FileDB {
 public:
  // Default constructor, uses BasicFilesystemOp.
  FileDB(const std::string &file_base, unsigned storage_depth);
  // Takes ownership of the FilesystemOp.
  FileDB(const std::string &file_base, unsigned storage_depth,
         FilesystemOp *file_op);
  ~FileDB();

  enum FileDBResult {
    OK,
    // Create failed.
    ENTRY_ALREADY_EXISTS,
    // Lookup or update failed.
    NOT_FOUND,
  };

  // Scan the entire database and return the list of keys.
  std::set<bstring> Scan() const;

  // Write (key, data) unless an entry matching |key| already exists.
  FileDBResult CreateEntry(const bstring &key, const bstring &data);

  // Update an existing entry; fail if it doesn't already exist.
  FileDBResult UpdateEntry(const bstring &key, const bstring &data);

  // Lookup entry based on key.
  FileDBResult LookupEntry(const bstring &key, bstring *result) const;

 private:
  std::string StoragePathBasename(const std::string &hex) const;
  std::string StoragePathComponent(const std::string &hex, unsigned n) const;
  std::string StoragePath(const bstring &key) const;
  bstring StorageKey(const std::string &storage_path) const;
  // Write or overwrite.
  void WriteStorageEntry(const bstring &key, const bstring &data);
  void ScanFiles(const std::string &dir_path,
                 std::set<bstring> *keys) const;
  void ScanDir(const std::string &dir_path,
               unsigned depth, std::set<bstring> *keys) const;

  // The following methods abort upon any error.
  bool FileExists(const std::string &file_path) const;
  void AtomicWriteBinaryFile(const std::string &file_path, const bstring &data);
  // Create directory, unless it already exists.
  void CreateMissingDirectory(const std::string &dir_path);

  const std::string storage_dir_;
  const std::string tmp_dir_;
  const std::string tmp_file_template_;
  unsigned int storage_depth_;
  FilesystemOp *file_op_;
};
#endif
