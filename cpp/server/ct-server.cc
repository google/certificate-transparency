/* -*- indent-tabs-mode: nil -*- */

#include <deque>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "include/ct.h"
#include "log/cert_checker.h"
#include "log/cert_submission_handler.h"
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
#include "proto/serializer.h"
#include "server/event.h"
#include "util/read_private_key.h"
#include "util/util.h"  // FIXME: debug

DEFINE_int32(port, 0, "Server port");
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

using cert_trans::util::ReadPrivateKey;
using ct::CertChecker;
using ct::LoggedCertificate;
using google::RegisterFlagValidator;
using std::string;

// Basic sanity checks on flag values.
static bool ValidatePort(const char *flagname, int port) {
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

using ct::MerkleAuditProof;
using ct::ClientLookup;
using ct::ClientMessage;
using ct::ServerError;
using ct::ServerMessage;
using ct::SignedCertificateTimestamp;
using ct::protocol::kPacketPrefixLength;
using ct::protocol::kMaxPacketLength;

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

  // Submit an entry and write a token, if the entry is accepted,
  // or an error otherwise.
  LogReply SubmitEntry(ct::LogEntryType type, const string &data,
                       SignedCertificateTimestamp *sct, string *error) {
    SignedCertificateTimestamp local_sct;
    SubmitResult submit_result = frontend_->QueueEntry(type, data, &local_sct);

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
                              ct::MerkleAuditProof *proof) {
    ct::MerkleAuditProof local_proof;
    LogLookup<LoggedCertificate>::LookupResult res =
        lookup_->AuditProof(merkle_leaf_hash, &local_proof);
    if (res == LogLookup<LoggedCertificate>::OK) {
      proof->CopyFrom(local_proof);
      return MERKLE_AUDIT_PROOF;
    }
    CHECK_EQ(LogLookup<LoggedCertificate>::NOT_FOUND, res);
    return NOT_FOUND;
  }

  bool SignMerkleTree() {
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

 private:
  Frontend *frontend_;
  TreeSigner<LoggedCertificate> *signer_;
  LogLookup<LoggedCertificate> *lookup_;
};

class FrontendLogEvent : public RepeatedEvent {
 public:
  FrontendLogEvent(time_t frequency, CTLogManager *manager)
  : RepeatedEvent(frequency),
    manager_(manager) {}

  string Description() {
    return "frontend statistics logging";
  }

  void Execute() {
    time_t roughly_now = Services::RoughTime();
    LOG(INFO) << "Frontend statistics on " << ctime(&roughly_now);
    LOG(INFO) << manager_->FrontendStats();
  }
 private:
  CTLogManager *manager_;
};


class TreeSigningEvent : public RepeatedEvent {
 public:
  TreeSigningEvent(time_t frequency, CTLogManager *manager)
  : RepeatedEvent(frequency),
    manager_(manager) {}

  string Description() {
    return "tree signing";
  }

  void Execute() {
    CHECK(manager_->SignMerkleTree());
   }
  private:
   CTLogManager *manager_;
};

class CTServer : public Server {
 public:
  // Does not grab ownership of the manager.
  CTServer(EventLoop *loop, int fd, CTLogManager *manager)
      : Server(loop, fd),
        manager_(manager) {}

  static const ct::protocol::Version kProtocolVersion = ct::protocol::V1;
  static const ct::protocol::Format kPacketFormat = ct::protocol::PROTOBUF;
  // Version in protobufs should match protocol version.
  static const ct::Version kCtVersion = ct::V1;

 private:
  void BytesRead(string *rbuffer) {
    for ( ; ; ) {
      if (rbuffer->size() < 5)
        return;
      size_t length = kMaxPacketLength + 1;
      // Just DCHECK: we explicitly feed it the right-size input,
      // so nothing should really go wrong here.
      Deserializer::DeserializeResult res =
          Deserializer::DeserializeUint(rbuffer->substr(2, 3), 3, &length);
      DCHECK_EQ(Deserializer::OK, res);
      if (rbuffer->size() < length + 5)
        return;
      // Can only really happen if max packet length is not aligned with
      // byte boundaries.
      if (length > kMaxPacketLength) {
        Close();
        return;
      }
      // We have to initialize to make the compiler happy,
      // so initialize to an invalid enum.
      int version = -1;
      int format = -1;
      res = Deserializer::DeserializeUint(rbuffer->substr(0, 1), 1, &version);
      DCHECK_EQ(Deserializer::OK, res);
      res = Deserializer::DeserializeUint(rbuffer->substr(1, 1), 1, &format);
      DCHECK_EQ(Deserializer::OK, res);
      PacketRead(version, format, rbuffer->substr(5, length));
      rbuffer->erase(0, length + 5);
    }
  }

  void PacketRead(int version, int format, const string &data) {
    if (version != kProtocolVersion) {
      SendError(ServerError::BAD_VERSION);
      return;
    }

    if (format != kPacketFormat) {
      SendError(ServerError::UNSUPPORTED_FORMAT);
      return;
    }

   ClientMessage message;
   if (!message.ParseFromString(data)) {
     SendError(ServerError::INVALID_MESSAGE);
     return;
   }

   LOG(INFO) << "Command is " << message.command() << ", data length "
             << message.submission_data().size();

   // Since we successfully parsed the protobuf, apparently we know
   // the command but don't handle it.
   if (message.command() != ClientMessage::SUBMIT_BUNDLE &&
       message.command() != ClientMessage::SUBMIT_CA_BUNDLE &&
       (message.command() != ClientMessage::LOOKUP_AUDIT_PROOF
        || message.lookup().type() !=
        ClientLookup::MERKLE_AUDIT_PROOF_BY_LEAF_HASH)) {
         SendError(ServerError::UNSUPPORTED_COMMAND);
         return;
       }

   if (message.command() == ClientMessage::SUBMIT_BUNDLE ||
       message.command() == ClientMessage::SUBMIT_CA_BUNDLE) {
     string error;
     SignedCertificateTimestamp sct;
     CTLogManager::LogReply reply;
     if (message.command() == ClientMessage::SUBMIT_BUNDLE)
       reply = manager_->SubmitEntry(ct::X509_ENTRY,
                                     message.submission_data(), &sct, &error);
     else
       reply = manager_->SubmitEntry(ct::PRECERT_ENTRY,
                                     message.submission_data(), &sct,  &error);

     switch (reply) {
       case CTLogManager::REJECT:
         SendError(ServerError::REJECTED, error);
         break;
       case CTLogManager::SIGNED_CERTIFICATE_TIMESTAMP:
         SendSCTToken(sct);
         break;
       default:
         DLOG(FATAL) << "Unknown CTLogManager reply: " << reply;
     }
   }

   if (message.command() == ClientMessage::LOOKUP_AUDIT_PROOF) {
     MerkleAuditProof proof;
     CTLogManager::LookupReply reply =
         manager_->QueryAuditProof(message.lookup().merkle_leaf_hash(),
                                   &proof);
     if (reply == CTLogManager::MERKLE_AUDIT_PROOF) {
       SendMerkleProof(proof);
     } else {
       CHECK_EQ(CTLogManager::NOT_FOUND, reply);
       SendError(ServerError::NOT_FOUND);
     }
   }
  }

  void SendError(ServerError::ErrorCode error) {
    SendError(error, "");
  }

  void SendError(ServerError::ErrorCode error, const string &error_string) {
    ServerMessage message;
    message.set_response(ServerMessage::ERROR);
    message.mutable_error()->set_code(error);
    message.mutable_error()->set_error_message(error_string);

    SendMessage(message);
  }

  void SendSCTToken(const SignedCertificateTimestamp &sct) {
    CHECK_EQ(kCtVersion, sct.version());
    ServerMessage message;
    message.set_response(ServerMessage::SIGNED_CERTIFICATE_TIMESTAMP);
    message.mutable_sct()->CopyFrom(sct);
    SendMessage(message);
  }

  void SendMerkleProof(const MerkleAuditProof &proof) {
    CHECK_EQ(kCtVersion, proof.version());
    ServerMessage message;
    message.set_response(ServerMessage::MERKLE_AUDIT_PROOF);
    message.mutable_merkle_proof()->CopyFrom(proof);
    SendMessage(message);
  }

  void SendMessage(const ServerMessage &message) {
    string serialized_message;
    CHECK(message.SerializeToString(&serialized_message));
    // TODO(ekasper): remove the CHECK; it's temporary until we decide
    // how to split large messages.
    CHECK_LE(serialized_message.size(), kMaxPacketLength) <<
        "Attempted to send a message that exceeds maximum packet length.";

    Write(Serializer::SerializeUint(kProtocolVersion, 1));
    Write(Serializer::SerializeUint(kPacketFormat, 1));
    Write(Serializer::SerializeUint(serialized_message.length(),
                                    kPacketPrefixLength));
    Write(serialized_message);
  }

  CTLogManager *manager_;
};

const ct::Version CTServer::kCtVersion;

class CTServerListener : public Listener {
 public:
  CTServerListener(EventLoop *loop, int fd,
                   CTLogManager *manager) : Listener(loop, fd),
                                            manager_(manager) {}

  void Accepted(int fd) {
    LOG(INFO) << "Accepted fd " << fd << std::endl;
    new CTServer(loop(), fd, manager_);
  }
 private:
  CTLogManager *manager_;
};

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  ct::LoadCtExtensions();

  EVP_PKEY *pkey = NULL;
  CHECK_EQ(ReadPrivateKey(&pkey, FLAGS_key), cert_trans::util::KEY_OK);

  int fd;
  CHECK(Services::InitServer(&fd, FLAGS_port, NULL, SOCK_STREAM));

  EventLoop loop;

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

  Services::SetRoughTime();
  TreeSigningEvent tree_event(FLAGS_tree_signing_frequency_seconds, &manager);
  FrontendLogEvent frontend_event(FLAGS_log_stats_frequency_seconds, &manager);
  loop.Add(&frontend_event);
  loop.Add(&tree_event);
  CTServerListener l(&loop, fd, &manager);
  LOG(INFO) << "Server listening on port " << FLAGS_port;
  loop.Forever();
}
