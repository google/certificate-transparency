/* -*- indent-tabs-mode: nil -*- */

#include <boost/asio.hpp>
// Note that this comes from cpp-netlib, not boost.
#include <boost/network/protocol/http/server.hpp>
#include <boost/network/uri.hpp>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string>

#include "log/cert.h"
#include "log/cert_checker.h"
#include "log/ct_extensions.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/frontend.h"
#include "log/frontend_signer.h"
#include "log/log_lookup.h"
#include "log/log_signer.h"
#include "log/logged_certificate.h"
#include "log/sqlite_db.h"
#include "log/tree_signer.h"
#include "proto/ct.pb.h"
#include "util/json_wrapper.h"
#include "util/openssl_util.h"

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

namespace http = boost::network::http;
namespace uri = boost::network::uri;

using ct::Cert;
using ct::CertChain;
using ct::CertChecker;
using ct::LoggedCertificate;
using ct::PreCertChain;
using ct::ShortMerkleAuditProof;
using ct::SignedCertificateTimestamp;
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
class RepeatedEvent {
 public:
  RepeatedEvent(boost::shared_ptr<boost::asio::io_service> io,
                boost::posix_time::time_duration frequency)
    : frequency_(frequency), timer_(*io, frequency) {
    Wait();
  }

protected:
  virtual void Execute() = 0;

 private:
  static void Call(const boost::system::error_code& /*e*/,
                   RepeatedEvent *event) {
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

class CTLogManager {
 public:
  CTLogManager(Frontend *frontend,
               TreeSigner<LoggedCertificate> *signer,
               LogLookup<LoggedCertificate> *lookup)
      : frontend_(frontend),
        signer_(signer),
        lookup_(lookup) {
    LOG(INFO) << "Starting CT log manager";
    time_t last_update = static_cast<time_t>(signer_->LastUpdateTime() / 1000);
    if (last_update > 0)
      LOG(INFO) << "Last tree update was at " << ctime(&last_update);
}

  ~CTLogManager() {
    delete frontend_;
    delete signer_;
    delete lookup_;
  }

  enum LogReply {
    SIGNED_CERTIFICATE_TIMESTAMP,
    REJECT,
  };

  enum LookupReply {
    MERKLE_AUDIT_PROOF,
    NOT_FOUND,
  };

  string FrontendStats() const {
    Frontend::FrontendStats stats;
    frontend_->GetStats(&stats);
    std::stringstream ss;
    ss << "Accepted X509 certificates: "
       << stats.x509_accepted << std::endl;
    ss << "Duplicate X509 certificates: "
       << stats.x509_duplicates << std::endl;
    ss << "Bad PEM X509 certificates: "
       << stats.x509_bad_pem_certs << std::endl;
    ss << "Too long X509 certificates: "
       << stats.x509_too_long_certs << std::endl;
    ss << "X509 verify errors: "
       << stats.x509_verify_errors << std::endl;
    ss << "Accepted precertificates: "
       << stats.precert_accepted << std::endl;
    ss << "Duplicate precertificates: "
       << stats.precert_duplicates << std::endl;
    ss << "Bad PEM precertificates: "
       << stats.precert_bad_pem_certs << std::endl;
    ss << "Too long precertificates: "
       << stats.precert_too_long_certs << std::endl;
    ss << "Precertificate verify errors: "
       << stats.precert_verify_errors << std::endl;
    ss << "Badly formatted precertificates: "
       << stats.precert_format_errors << std::endl;
   ss << "Internal errors: "
       << stats.internal_errors << std::endl;
    return ss.str();
  }

  LogReply SubmitEntry(CertChain *chain, SignedCertificateTimestamp *sct,
                           string *error) const {
    SignedCertificateTimestamp local_sct;
    SubmitResult submit_result = chain->Submit(frontend_, &local_sct);

    LogReply reply = REJECT;
    switch (submit_result) {
      case ADDED:
      case DUPLICATE:
        sct->CopyFrom(local_sct);
        reply = SIGNED_CERTIFICATE_TIMESTAMP;
        break;
      default:
        error->assign(Frontend::SubmitResultString(submit_result));
        break;
    }
    return reply;
  }

  LookupReply QueryAuditProof(const std::string &merkle_leaf_hash,
                              size_t tree_size,
                              ct::ShortMerkleAuditProof *proof) const {
    ct::ShortMerkleAuditProof local_proof;
    LogLookup<LoggedCertificate>::LookupResult res =
        lookup_->AuditProof(merkle_leaf_hash, tree_size, &local_proof);
    if (res == LogLookup<LoggedCertificate>::OK) {
      proof->CopyFrom(local_proof);
      return MERKLE_AUDIT_PROOF;
    }
    CHECK_EQ(LogLookup<LoggedCertificate>::NOT_FOUND, res);
    return NOT_FOUND;
  }

  bool SignMerkleTree() const {
    TreeSigner<LoggedCertificate>::UpdateResult res = signer_->UpdateTree();
    if (res != TreeSigner<LoggedCertificate>::OK) {
      LOG(ERROR) << "Tree update failed with return code " << res;
      return false;
    }
    time_t last_update = static_cast<time_t>(signer_->LastUpdateTime() / 1000);
    LOG(INFO) << "Tree successfully updated at " << ctime(&last_update);
    CHECK_EQ(LogLookup<LoggedCertificate>::UPDATE_OK, lookup_->Update());
    return true;
  }

  const ct::SignedTreeHead GetSTH() const {
    return signer_->LatestSTH();
  }

  std::vector<string> GetConsistency(size_t first, size_t second) const {
    return lookup_->ConsistencyProof(first, second);
  }

 private:
  Frontend *frontend_;
  TreeSigner<LoggedCertificate> *signer_;
  LogLookup<LoggedCertificate> *lookup_;
};

class TreeSigningEvent : public RepeatedEvent {
 public:
  TreeSigningEvent(boost::shared_ptr<boost::asio::io_service> io,
                   boost::posix_time::time_duration frequency,
                   CTLogManager *manager)
      : RepeatedEvent(io, frequency),
        manager_(manager) {}

  void Execute() {
    CHECK(manager_->SignMerkleTree());
   }

  private:
   CTLogManager *manager_;
};

class ct_server;
typedef http::server<ct_server> server;

class ct_server {
 public:
  ct_server(CTLogManager *manager) : manager_(manager) {}

  void operator() (server::request const &request,
                   server::response &response) {
    VLOG(1) << "[" << string(source(request))
            << "]: source = " << request.source
            << " destination = " << request.destination
            << " method = " << request.method
            << " status = " << response.status << '\n';

    // This is kinda incredibly dumb, but cpp-netlib can't do any better.
    uri::uri uri(string("http://x") + request.destination);
    string path = uri.path();

    if (request.method == "GET") {
      if (path == "/ct/v1/get-sth")
        GetSTH(response);
      else if (path == "/ct/v1/get-proof-by-hash")
        GetProof(response, uri);
      else if (path == "/ct/v1/get-sth-consistency")
        GetConsistency(response, uri);
      else
        response = server::response::stock_reply(server::response::not_found,
                                                 "Not found");
    } else if (request.method == "POST") {
      if (path == "/ct/v1/add-chain")
        AddChain(response, request.body);
      else if (path == "/ct/v1/add-pre-chain")
        AddPreChain(response, request.body);
      else
        response = server::response::stock_reply(server::response::not_found,
                                                 "Not found");
    }
  }

  void log(const std::string &err) {
    LOG(ERROR) << err;
  }

private:
  void GetConsistency(server::response &response, const uri::uri &uri) {
    std::map<string, string> qmap;
    uri::query_map(uri, qmap);
    size_t first = atoi(qmap["first"].c_str());
    size_t second = atoi(qmap["second"].c_str());

    std::vector<string> consistency = manager_->GetConsistency(first, second);

    JsonArray jcons;
    for (std::vector<string>::const_iterator i = consistency.begin();
         i != consistency.end(); ++i)
      jcons.AddBase64(*i);

    JsonObject jsend;
    jsend.Add("consistency", jcons);

    response.status = server::response::ok;
    response.content = jsend.ToString();
  }

  void GetProof(server::response &response, const uri::uri &uri) {
    std::map<string, string> qmap;
    uri::query_map(uri, qmap);
    string b64hash = uri::decoded(qmap["hash"]);
    size_t tree_size = atoi(qmap["tree_size"].c_str());

    const ct::SignedTreeHead &sth = manager_->GetSTH();
    if (tree_size > sth.tree_size()) {
      response.status = server::response::bad_request;
      response.content = "Tree is not that big";
      return;
    }

    ShortMerkleAuditProof proof;
    CTLogManager::LookupReply reply
        = manager_->QueryAuditProof(util::FromBase64(b64hash.c_str()),
                                    tree_size, &proof);
    if (reply == CTLogManager::NOT_FOUND) {
      response.status = server::response::bad_request;
      response.content = "Couldn't find hash";
      return;
    }

    CHECK_EQ(CTLogManager::MERKLE_AUDIT_PROOF, reply);

    JsonArray audit;
    for (int n = 0; n < proof.path_node_size(); ++n)
      audit.AddBase64(proof.path_node(n));

    JsonObject jsend;
    jsend.Add("leaf_index", proof.leaf_index());
    jsend.Add("audit_path", audit);

    response.status = server::response::ok;
    response.content = jsend.ToString();
  }

  void GetSTH(server::response &response) {
    const ct::SignedTreeHead &sth = manager_->GetSTH();
    response.status = server::response::ok;

    VLOG(1) << "STH is " << sth.DebugString();

    JsonObject jsend;
    jsend.Add("tree_size", sth.tree_size());
    jsend.Add("timestamp", sth.timestamp());
    jsend.AddBase64("sha256_root_hash", sth.sha256_root_hash());
    jsend.Add("tree_head_signature", sth.signature());

    response.content = jsend.ToString();
  }

  void AddChain(server::response &response, const std::string &body) {
    CertChain chain;
    AddChain(response, body, &chain);
  }

  void AddPreChain(server::response &response, const std::string &body) {
    PreCertChain chain;
    AddChain(response, body, &chain);
  }

  void AddChain(server::response &response, const std::string &body,
                CertChain *chain) {
    if (!ExtractChain(response, chain, body))
      return;

    SignedCertificateTimestamp sct;
    string error;
    CTLogManager::LogReply result = manager_->SubmitEntry(chain, &sct, &error);

    ProcessChainResult(response, result, error, sct);
  }

  static bool ExtractChain(server::response &response, CertChain *chain,
                           const string &body) {
    JsonObject jbody(body);

    JsonArray jchain(jbody, "chain");
    if (!jchain.Ok()) {
      response.status = server::response::bad_request;
      response.content = "Couldn't extract chain";
      LOG(INFO) << "Couldn't extract chain from " << body;
      return false;
    }

    for (int n = 0; n < jchain.Length(); ++n) {
      JsonString jcert(jchain, n);
      string cert_der = jcert.FromBase64();
      X509 *x509 = NULL;
      const unsigned char *in
          = reinterpret_cast<const unsigned char *>(cert_der.data());
      x509 = d2i_X509(&x509, &in, cert_der.length());
      if (x509 == NULL) {
        response.status = server::response::bad_request;
        response.content = "Couldn't decode certificate";
        return false;
      }
      Cert *cert = new Cert(x509);
      if (!cert->IsLoaded()) {
        delete cert;
        response.status = server::response::bad_request;
        response.content = "Couldn't load certificate";
        LOG(INFO) << "Couldn't load certificate " << jcert.Value();
        return false;
      }
      chain->AddCert(cert);
    }

    return true;
  }

  void ProcessChainResult(server::response &response,
                          CTLogManager::LogReply result, const string &error,
                          const SignedCertificateTimestamp &sct) {
    LOG(INFO) << "Chain added, result = " << result << ", error = " << error;

    JsonObject jsend;
    if (result == CTLogManager::REJECT) {
      jsend.AddBoolean("success", false);
      jsend.Add("reason",error);
      response.status = server::response::bad_request;
    } else {
      jsend.Add("sct_version", (int64_t)0);
      jsend.AddBase64("id", sct.id().key_id());
      jsend.Add("timestamp",sct.timestamp());
      jsend.Add("extensions", "");
      jsend.Add("signature", sct.signature());
      response.status = server::response::ok;
    }
    response.content = jsend.ToString();
  }

  const CTLogManager *manager_;
};

int main(int argc, char * argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  ct::LoadCtExtensions();

  EVP_PKEY *pkey = NULL;
  CHECK(util::ReadPrivateKey(&pkey, FLAGS_key));

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
  CHECK(util::ReadPrivateKey(&pkey2, FLAGS_key));

  CTLogManager manager(
      new Frontend(new CertSubmissionHandler(&checker),
                   new FrontendSigner(db, new LogSigner(pkey))),
      new TreeSigner<LoggedCertificate>(db, new LogSigner(pkey2)),
      new LogLookup<LoggedCertificate>(db));

  try {
    ct_server handler(&manager);
    boost::shared_ptr<boost::asio::io_service> io
        = boost::make_shared<boost::asio::io_service>();
    TreeSigningEvent tree_event(io,
        boost::posix_time::seconds(FLAGS_tree_signing_frequency_seconds),
        &manager);
    server::options options(handler);
    server server_(options.address(FLAGS_server).port(FLAGS_port)
                   .reuse_address(true).io_service(io));
    server_.run();
  }
  catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }

  return 0;
}
