#include "log/strict_consistent_store.h"
#include "server/server.h"
#include "server/server_helper.h"

using cert_trans::Server;
using google::RegisterFlagValidator;
using std::string;
using std::unique_ptr;

// TODO(alcutter): Just specify a root dir with a single flag.
DEFINE_string(cert_dir, "", "Storage directory for certificates");
DEFINE_string(tree_dir, "", "Storage directory for trees");
DEFINE_string(meta_dir, "", "Storage directory for meta info");
DEFINE_string(sqlite_db, "",
              "SQLite database for certificate and tree storage");
DEFINE_string(leveldb_db, "",
              "LevelDB database for certificate and tree storage");
// TODO(ekasper): sanity-check these against the directory structure.
DEFINE_int32(cert_storage_depth, 0,
             "Subdirectory depth for certificates; if the directory is not "
             "empty, must match the existing depth.");
DEFINE_int32(tree_storage_depth, 0,
             "Subdirectory depth for tree signatures; if the directory is not "
             "empty, must match the existing depth");

static bool ValidateWrite(const char* flagname, const string& path) {
  if (path != "" && access(path.c_str(), W_OK) != 0) {
    std::cout << "Cannot modify " << flagname << " at " << path << std::endl;
    return false;
  }
  return true;
}

static bool ValidateIsNonNegative(const char* flagname, int value) {
  if (value < 0) {
    std::cout << flagname << " must not be negative" << std::endl;
    return false;
  }
  return true;
}

static const bool cert_dir_dummy =
    RegisterFlagValidator(&FLAGS_cert_dir, &ValidateWrite);

static const bool tree_dir_dummy =
    RegisterFlagValidator(&FLAGS_tree_dir, &ValidateWrite);

static const bool c_st_dummy =
    RegisterFlagValidator(&FLAGS_cert_storage_depth, &ValidateIsNonNegative);

static const bool t_st_dummy =
    RegisterFlagValidator(&FLAGS_tree_storage_depth, &ValidateIsNonNegative);

namespace cert_trans {

void EnsureValidatorsRegistered() {
  CHECK(cert_dir_dummy && tree_dir_dummy && c_st_dummy && t_st_dummy);
}


unique_ptr<Database> ProvideDatabase() {
  if (!FLAGS_sqlite_db.empty() + !FLAGS_leveldb_db.empty() +
          (!FLAGS_cert_dir.empty() | !FLAGS_tree_dir.empty()) !=
      1) {
    LOG(FATAL) << "Must specify exactly one database type. Check flags.";
  }

  if (FLAGS_sqlite_db.empty() && FLAGS_leveldb_db.empty()) {
    CHECK_NE(FLAGS_cert_dir, FLAGS_tree_dir)
        << "Certificate directory and tree directory must differ";
  }

  if (!FLAGS_sqlite_db.empty()) {
    return unique_ptr<Database>(new SQLiteDB(FLAGS_sqlite_db));
  } else if (!FLAGS_leveldb_db.empty()) {
    return unique_ptr<Database>(new LevelDB(FLAGS_leveldb_db));
  } else {
    return unique_ptr<Database>(
        new FileDB(new FileStorage(FLAGS_cert_dir, FLAGS_cert_storage_depth),
                   new FileStorage(FLAGS_tree_dir, FLAGS_tree_storage_depth),
                   new FileStorage(FLAGS_meta_dir, 0)));
  }

  LOG(FATAL) << "No usable database is configured by flags";
}

}  // namespace cert_trans
