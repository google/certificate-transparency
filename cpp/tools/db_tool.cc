#include <functional>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <limits.h>
#include <memory>

#include "log/database.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/leveldb_db.h"
#include "log/logged_certificate.h"
#include "log/sqlite_db.h"
#include "proto/serializer.h"
#include "util/init.h"
#include "util/util.h"

DEFINE_string(cert_dir, "", "Storage directory for certificates");
DEFINE_string(tree_dir, "", "Storage directory for trees");
DEFINE_string(meta_dir, "", "Storage directory for meta info");
DEFINE_int32(cert_storage_depth, 0,
             "Subdirectory depth for certificates; if the directory is not "
             "empty, must match the existing depth.");
DEFINE_int32(tree_storage_depth, 0,
             "Subdirectory depth for tree signatures; if the directory is not "
             "empty, must match the existing depth");
DEFINE_string(sqlite_db, "",
              "SQLite database for certificate and tree storage");
DEFINE_string(leveldb_db, "",
              "LevelDB database for certificate and tree storage");

DEFINE_int64(start, 0, "Starting sequence number (inclusive).");
DEFINE_int64(end, std::numeric_limits<int64_t>::max(),
             "Ending sequence number (inclusive).");

using cert_trans::FileStorage;
using cert_trans::LoggedCertificate;
using std::cerr;
using std::cout;
using std::function;
using std::string;
using std::unique_ptr;
using util::InitCT;
using util::ToBase64;


void Usage() {
  cerr << "Usage: db_tool [flags] <command>\n"
       << "Where <command> is one of:\n"
       << "  dump_leaf_inputs\n";
}


void ForEachLeaf(const ReadOnlyDatabase<LoggedCertificate>* db,
                 const function<void(const LoggedCertificate& cert)>& f) {
  unique_ptr<ReadOnlyDatabase<LoggedCertificate>::Iterator> it(
      db->ScanEntries(FLAGS_start));
  LoggedCertificate cert;
  while (it->GetNextEntry(&cert)) {
    if (cert.sequence_number() > FLAGS_end) {
      break;
    }
    f(cert);
  }
}


int DumpLeafInputs(const ReadOnlyDatabase<LoggedCertificate>* db) {
  CHECK_NOTNULL(db);
  ForEachLeaf(db, [](const LoggedCertificate& cert) {
    string serialized;
    const Serializer::SerializeResult r(Serializer::SerializeSCTSignatureInput(
        cert.contents().sct(), cert.contents().entry(), &serialized));
    if (r != Serializer::OK) {
      LOG(FATAL) << "Failed to serialize entry with seq# "
                 << cert.sequence_number() << " : " << r;
    }

    cout << cert.sequence_number() << " " << ToBase64(serialized) << "\n";
  });
  return 0;
}


int main(int argc, char* argv[]) {
  InitCT(&argc, &argv);

  if (argc != 2) {
    Usage();
    return 1;
  }

  // ------8<----------8<---------8<-----------
  // TODO(alcutter): Refactor this out into a common CreateDatabase() call
  // somewhere.
  if (!FLAGS_sqlite_db.empty() + !FLAGS_leveldb_db.empty() +
          (!FLAGS_cert_dir.empty() | !FLAGS_tree_dir.empty()) !=
      1) {
    LOG(FATAL) << "Must only specify one database type.";
  }

  if (FLAGS_sqlite_db.empty() && FLAGS_leveldb_db.empty()) {
    CHECK_NE(FLAGS_cert_dir, FLAGS_tree_dir)
        << "Certificate directory and tree directory must differ";
  }

  unique_ptr<ReadOnlyDatabase<LoggedCertificate>> db;

  if (!FLAGS_sqlite_db.empty()) {
    db.reset(new SQLiteDB<LoggedCertificate>(FLAGS_sqlite_db));
  } else if (!FLAGS_leveldb_db.empty()) {
    db.reset(new LevelDB<LoggedCertificate>(FLAGS_leveldb_db));
  } else {
    db.reset(new FileDB<LoggedCertificate>(
        new FileStorage(FLAGS_cert_dir, FLAGS_cert_storage_depth),
        new FileStorage(FLAGS_tree_dir, FLAGS_tree_storage_depth),
        new FileStorage(FLAGS_meta_dir, 0)));
  }
  // ------8<----------8<---------8<-----------

  if (strcmp(argv[1], "dump_leaf_inputs") == 0) {
    return DumpLeafInputs(db.get());
  } else {
    Usage();
    return 1;
  }

  return 0;
}
