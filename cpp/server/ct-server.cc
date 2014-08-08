/* -*- indent-tabs-mode: nil -*- */

#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/signal_set.hpp>
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
#include "server/ct_log_manager.h"
#include "server/handler.h"
#include "util/read_private_key.h"

DEFINE_string(server, "localhost", "Server host");
DEFINE_string(port, "9999", "Server port");
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
             "Interval for logging summary statistics. Approximate: the server "
             "will log statistics if in the beginning of its select loop, "
             "at least this period has elapsed since the last log time. "
             "Must be greater than 0.");
DEFINE_int32(tree_signing_frequency_seconds, 600,
             "How often should we issue a new signed tree head. Approximate: "
             "the signer process will kick off if in the beginning of the "
             "server select loop, at least this period has elapsed since the "
             "last signing. Set this well below the MMD to ensure we sign "
             "in a timely manner. Must be greater than 0.");

using cert_trans::CTLogManager;
using cert_trans::HttpHandler;
using cert_trans::util::ReadPrivateKey;
using ct::CertChecker;
using ct::LoggedCertificate;
using google::RegisterFlagValidator;
using std::string;

// Basic sanity checks on flag values.
static bool ValidatePort(const char *flagname, const string &port_str) {
  int port = atoi(port_str.c_str());
  if (port <= 0 || port > 65535) {
    std::cout << "Port value " << port << " is invalid. " << std::endl;
    return false;
  }
  return true;
}

static const bool port_dummy = RegisterFlagValidator(&FLAGS_port,
                                                     &ValidatePort);

static bool ValidateRead(const char *flagname, const string &path) {
  if (access(path.c_str(), R_OK) != 0) {
    std::cout << "Cannot access " << flagname << " at " << path << std::endl;
    return false;
  }
  return true;
}

static const bool key_dummy = RegisterFlagValidator(&FLAGS_key,
                                                    &ValidateRead);

static const bool cert_dummy = RegisterFlagValidator(&FLAGS_trusted_cert_file,
                                                     &ValidateRead);

static bool ValidateWrite(const char *flagname, const string &path) {
  if (path != "" && access(path.c_str(), W_OK) != 0) {
    std::cout << "Cannot modify " << flagname << " at " << path << std::endl;
    return false;
  }
  return true;
}

static const bool cert_dir_dummy = RegisterFlagValidator(&FLAGS_cert_dir,
                                                         &ValidateWrite);

static const bool tree_dir_dummy = RegisterFlagValidator(&FLAGS_tree_dir,
                                                         &ValidateWrite);

static bool ValidateIsNonNegative(const char *flagname, int value) {
  if (value < 0) {
    std::cout << flagname << " must not be negative" << std::endl;
    return false;
  }
  return true;
}

static const bool c_st_dummy = RegisterFlagValidator(&FLAGS_cert_storage_depth,
                                                     &ValidateIsNonNegative);
static const bool t_st_dummy = RegisterFlagValidator(&FLAGS_tree_storage_depth,
                                                     &ValidateIsNonNegative);

static bool ValidateIsPositive(const char *flagname, int value) {
  if (value <= 0) {
    std::cout << flagname << " must be greater than 0" << std::endl;
    return false;
  }
  return true;
}

static const bool stats_dummy = RegisterFlagValidator(
    &FLAGS_log_stats_frequency_seconds, &ValidateIsPositive);

static const bool sign_dummy = RegisterFlagValidator(
    &FLAGS_tree_signing_frequency_seconds, &ValidateIsPositive);

// convert a boost single-shot timer (deadline_timer) into a repeat
// timer.
class AsioRepeatedEvent {
 public:
  AsioRepeatedEvent(boost::shared_ptr<boost::asio::io_service> io,
                    boost::posix_time::time_duration frequency)
    : frequency_(frequency), timer_(*io, frequency) {
    Wait();
  }

 protected:
  virtual void Execute() = 0;

 private:
  static void Call(const boost::system::error_code& /*e*/,
                   AsioRepeatedEvent *event) {
    event->Go();
  }

  void Wait() {
    timer_.async_wait(boost::bind(Call, boost::asio::placeholders::error,
                                  this));
  }

  void Go() {
    Execute();
    timer_.expires_at(timer_.expires_at() + frequency_);
    Wait();
  }

  boost::posix_time::time_duration frequency_;
  boost::asio::deadline_timer timer_;
};

class TreeSigningEvent : public AsioRepeatedEvent {
 public:
  TreeSigningEvent(boost::shared_ptr<boost::asio::io_service> io,
                   boost::posix_time::time_duration frequency,
                   CTLogManager *manager)
      : AsioRepeatedEvent(io, frequency),
        manager_(manager) {}

  void Execute() {
    CHECK(manager_->SignMerkleTree());
  }

 private:
  CTLogManager *manager_;
};

typedef boost::network::http::server<HttpHandler> server;

static void signal_handler(server* server, boost::asio::signal_set* sigset,
                           const boost::system::error_code& error,
                           int signal_number) {
  if (error)
    return;

  LOG(WARNING) << "received signal: " << strsignal(signal_number);
  sigset->remove(signal_number);
  server->stop();
}

int main(int argc, char * argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  ct::LoadCtExtensions();

  EVP_PKEY *pkey = NULL;
  CHECK_EQ(ReadPrivateKey(&pkey, FLAGS_key), cert_trans::util::KEY_OK);

  CertChecker checker;
  CHECK(checker.LoadTrustedCertificates(FLAGS_trusted_cert_file))
      << "Could not load CA certs from " << FLAGS_trusted_cert_file;

  if (FLAGS_sqlite_db == "")
    CHECK_NE(FLAGS_cert_dir, FLAGS_tree_dir)
        << "Certificate directory and tree directory must differ";

  if ((FLAGS_cert_dir != "" || FLAGS_tree_dir != "") && FLAGS_sqlite_db != "") {
    std::cerr << "Choose either file or sqlite database, not both" << std::endl;
    exit(1);
  }

  Database<LoggedCertificate> *db;

  if (FLAGS_sqlite_db != "")
      db = new SQLiteDB<LoggedCertificate>(FLAGS_sqlite_db);
  else
      db = new FileDB<LoggedCertificate>(
               new FileStorage(FLAGS_cert_dir, FLAGS_cert_storage_depth),
               new FileStorage(FLAGS_tree_dir, FLAGS_tree_storage_depth));

  // Hmm, there is no EVP_PKEY_dup, so let's read the key again...
  EVP_PKEY *pkey2 = NULL;
  CHECK_EQ(ReadPrivateKey(&pkey2, FLAGS_key), cert_trans::util::KEY_OK);

  CTLogManager manager(
      new Frontend(new CertSubmissionHandler(&checker),
                   new FrontendSigner(db, new LogSigner(pkey))),
      new TreeSigner<LoggedCertificate>(db, new LogSigner(pkey2)),
      new LogLookup<LoggedCertificate>(db));

  try {
    HttpHandler handler(&manager);
    boost::shared_ptr<boost::asio::io_service> io
        = boost::make_shared<boost::asio::io_service>();
    TreeSigningEvent tree_event(io,
        boost::posix_time::seconds(FLAGS_tree_signing_frequency_seconds),
        &manager);
    server::options options(handler);
    server server_(options.address(FLAGS_server).port(FLAGS_port)
                   .reuse_address(true).io_service(io));

    boost::asio::signal_set signals(*io, SIGINT, SIGTERM);
    signals.async_wait(boost::bind(
        &signal_handler, &server_, &signals, _1, _2));

    server_.run();
  }
  catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }

  return 0;
}
