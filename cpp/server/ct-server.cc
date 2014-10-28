/* -*- indent-tabs-mode: nil -*- */

#include <event2/thread.h>
#include <functional>
#include <gflags/gflags.h>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <string>

#include "log/cert_checker.h"
#include "log/cert_submission_handler.h"
#include "log/ct_extensions.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/frontend.h"
#include "log/frontend_signer.h"
#include "log/log_lookup.h"
#include "log/log_signer.h"
#include "log/sqlite_db.h"
#include "log/tree_signer.h"
#include "server/handler.h"
#include "util/libevent_wrapper.h"
#include "util/read_private_key.h"
#include "util/thread_pool.h"

DEFINE_string(server, "localhost", "Server host");
DEFINE_int32(port, 9999, "Server port");
DEFINE_string(key, "", "PEM-encoded server private key file");
DEFINE_string(trusted_cert_file, "",
              "File for trusted CA certificates, in concatenated PEM format");
DEFINE_string(cert_dir, "", "Storage directory for certificates");
DEFINE_string(tree_dir, "", "Storage directory for trees");
DEFINE_string(sqlite_db, "", "Database for certificate and tree storage");
// TODO(ekasper): sanity-check these against the directory structure.
DEFINE_int32(cert_storage_depth, 0,
             "Subdirectory depth for certificates; if the directory is not "
             "empty, must match the existing depth.");
DEFINE_int32(tree_storage_depth, 0,
             "Subdirectory depth for tree signatures; if the directory is not "
             "empty, must match the existing depth");
DEFINE_int32(log_stats_frequency_seconds, 3600,
             "Interval for logging summary statistics. Approximate: the "
             "server will log statistics if in the beginning of its select "
             "loop, at least this period has elapsed since the last log time. "
             "Must be greater than 0.");
DEFINE_int32(tree_signing_frequency_seconds, 600,
             "How often should we issue a new signed tree head. Approximate: "
             "the signer process will kick off if in the beginning of the "
             "server select loop, at least this period has elapsed since the "
             "last signing. Set this well below the MMD to ensure we sign in "
             "a timely manner. Must be greater than 0.");

namespace libevent = cert_trans::libevent;

using cert_trans::CertChecker;
using cert_trans::HttpHandler;
using cert_trans::LoggedCertificate;
using cert_trans::ThreadPool;
using cert_trans::util::ReadPrivateKey;
using google::RegisterFlagValidator;
using std::bind;
using std::function;
using std::make_shared;
using std::shared_ptr;
using std::string;

// Basic sanity checks on flag values.
static bool ValidatePort(const char* flagname, int port) {
  if (port <= 0 || port > 65535) {
    std::cout << "Port value " << port << " is invalid. " << std::endl;
    return false;
  }
  return true;
}

static const bool port_dummy =
    RegisterFlagValidator(&FLAGS_port, &ValidatePort);

static bool ValidateRead(const char* flagname, const string& path) {
  if (access(path.c_str(), R_OK) != 0) {
    std::cout << "Cannot access " << flagname << " at " << path << std::endl;
    return false;
  }
  return true;
}

static const bool key_dummy = RegisterFlagValidator(&FLAGS_key, &ValidateRead);

static const bool cert_dummy =
    RegisterFlagValidator(&FLAGS_trusted_cert_file, &ValidateRead);

static bool ValidateWrite(const char* flagname, const string& path) {
  if (path != "" && access(path.c_str(), W_OK) != 0) {
    std::cout << "Cannot modify " << flagname << " at " << path << std::endl;
    return false;
  }
  return true;
}

static const bool cert_dir_dummy =
    RegisterFlagValidator(&FLAGS_cert_dir, &ValidateWrite);

static const bool tree_dir_dummy =
    RegisterFlagValidator(&FLAGS_tree_dir, &ValidateWrite);

static bool ValidateIsNonNegative(const char* flagname, int value) {
  if (value < 0) {
    std::cout << flagname << " must not be negative" << std::endl;
    return false;
  }
  return true;
}

static const bool c_st_dummy =
    RegisterFlagValidator(&FLAGS_cert_storage_depth, &ValidateIsNonNegative);
static const bool t_st_dummy =
    RegisterFlagValidator(&FLAGS_tree_storage_depth, &ValidateIsNonNegative);

static bool ValidateIsPositive(const char* flagname, int value) {
  if (value <= 0) {
    std::cout << flagname << " must be greater than 0" << std::endl;
    return false;
  }
  return true;
}

static const bool stats_dummy =
    RegisterFlagValidator(&FLAGS_log_stats_frequency_seconds,
                          &ValidateIsPositive);

static const bool sign_dummy =
    RegisterFlagValidator(&FLAGS_tree_signing_frequency_seconds,
                          &ValidateIsPositive);

// Hooks a repeating timer on the event loop to call a callback. It
// will wait "interval_secs" between calls to "callback" (so this
// means that if "callback" takes some time, it will run less
// frequently).
class PeriodicCallback {
 public:
  PeriodicCallback(const shared_ptr<libevent::Base>& base, int interval_secs,
                   const function<void()>& callback)
      : base_(base),
        interval_secs_(interval_secs),
        event_(*base_, -1, 0, bind(&PeriodicCallback::Go, this)),
        callback_(callback) {
    event_.Add(interval_secs_);
  }

 private:
  void Go() {
    callback_();
    event_.Add(interval_secs_);
  }

  const shared_ptr<libevent::Base> base_;
  const int interval_secs_;
  libevent::Event event_;
  const function<void()> callback_;

  DISALLOW_COPY_AND_ASSIGN(PeriodicCallback);
};

void SignMerkleTree(TreeSigner<LoggedCertificate>* tree_signer,
                    LogLookup<LoggedCertificate>* log_lookup) {
  CHECK_EQ(tree_signer->UpdateTree(), TreeSigner<LoggedCertificate>::OK);
}

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  cert_trans::LoadCtExtensions();

  EVP_PKEY* pkey = NULL;
  CHECK_EQ(ReadPrivateKey(&pkey, FLAGS_key), cert_trans::util::KEY_OK);
  LogSigner log_signer(pkey);

  CertChecker checker;
  CHECK(checker.LoadTrustedCertificates(FLAGS_trusted_cert_file))
      << "Could not load CA certs from " << FLAGS_trusted_cert_file;

  if (FLAGS_sqlite_db == "")
    CHECK_NE(FLAGS_cert_dir, FLAGS_tree_dir)
        << "Certificate directory and tree directory must differ";

  if ((FLAGS_cert_dir != "" || FLAGS_tree_dir != "") &&
      FLAGS_sqlite_db != "") {
    std::cerr << "Choose either file or sqlite database, not both"
              << std::endl;
    exit(1);
  }

  Database<LoggedCertificate>* db;

  if (FLAGS_sqlite_db != "")
    db = new SQLiteDB<LoggedCertificate>(FLAGS_sqlite_db);
  else
    db = new FileDB<LoggedCertificate>(
        new FileStorage(FLAGS_cert_dir, FLAGS_cert_storage_depth),
        new FileStorage(FLAGS_tree_dir, FLAGS_tree_storage_depth));

  evthread_use_pthreads();
  const shared_ptr<libevent::Base> event_base(make_shared<libevent::Base>());

  Frontend frontend(new CertSubmissionHandler(&checker),
                    new FrontendSigner(db, &log_signer));
  TreeSigner<LoggedCertificate> tree_signer(db, &log_signer);
  LogLookup<LoggedCertificate> log_lookup(db);

  // Make sure that we have an STH, even if the tree is empty.
  // TODO(pphaneuf): We should be remaining in an "unhealthy state"
  // (either not accepting any requests, or returning some internal
  // server error) until we have an STH to serve. We can sign for now,
  // but we might not be a signer.
  SignMerkleTree(&tree_signer, &log_lookup);

  ThreadPool pool;
  HttpHandler handler(&log_lookup, db, &checker, &frontend, &pool);

  PeriodicCallback tree_event(event_base, FLAGS_tree_signing_frequency_seconds,
                              bind(&SignMerkleTree, &tree_signer,
                                   &log_lookup));

  libevent::HttpServer server(*event_base);
  handler.Add(&server);
  server.Bind(NULL, FLAGS_port);

  event_base->Dispatch();

  return 0;
}
