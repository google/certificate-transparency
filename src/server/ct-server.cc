/* -*- indent-tabs-mode: nil -*- */

#include <deque>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "cert_checker.h"
#include "cert_submission_handler.h"
#include "ct.h"
#include "ct.pb.h"
#include "file_db.h"
#include "file_storage.h"
#include "frontend_signer.h"
#include "log_signer.h"
#include "serializer.h"
#include "sqlite_db.h"
#include "types.h"
#include "unistd.h"

DEFINE_int32(port, 0, "Server port");
DEFINE_string(key, "", "PEM-encoded server private key file");
DEFINE_string(trusted_cert_dir, "",
              "Directory for trusted CA certificates, in OpenSSL hash format");
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

using google::RegisterFlagValidator;

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

static bool ValidateRead(const char *flagname, const std::string &path) {
  if (access(path.c_str(), R_OK) != 0) {
    std::cout << "Cannot access " << flagname << " at " << path << std::endl;
    return false;
  }
  return true;
}

static const bool key_dummy = RegisterFlagValidator(&FLAGS_key,
                                                    &ValidateRead);

static const bool cert_dummy = RegisterFlagValidator(&FLAGS_trusted_cert_dir,
                                                     &ValidateRead);

static bool ValidateWrite(const char *flagname, const std::string &path) {
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

using ct::CertificateEntry;
using ct::ClientMessage;
using ct::ServerError;
using ct::ServerMessage;
using ct::SignedCertificateTimestamp;

class EventLoop;

class Services {
 public:

  // because time is expensive, for most tasks we can just use some
  // time sampled within this event handling loop. So, the main loop
  // needs to call SetRoughTime() appropriately.
  static time_t RoughTime() {
    if (rough_time_ == 0)
      rough_time_ = time(NULL);
    return rough_time_;
  }

  static void SetRoughTime() { rough_time_ = 0; }

 private:

  static time_t rough_time_;
};

time_t Services::rough_time_;

class FD {
 public:

  enum CanDelete {
    DELETE,
    NO_DELETE
  };

  FD(EventLoop *loop, int fd, CanDelete deletable = DELETE);

  virtual ~FD() {}

  virtual bool WantsWrite() const = 0;

  virtual void WriteIsAllowed() = 0;

  virtual bool WantsRead() const = 0;

  virtual void ReadIsAllowed() = 0;

  bool WantsErase() const { return wants_erase_; }

  void Close() {
    DCHECK_EQ(deletable_, DELETE) << "Can't call Close() on a non-deletable FD";
    if (wants_erase_) {
      LOG(INFO) << "Attempting to close an already closed fd " << fd();
      return;
    }
    LOG(INFO) << "Closing fd " << fd() << std::endl;
    wants_erase_ = true;
    shutdown(fd(), SHUT_RDWR);
    close(fd());
  }

  int fd() const { return fd_; }

  bool CanDrop() const { return deletable_ == DELETE; }

  // Don't forget to call me if anything happens!
  // FIXME: time() is expensive - just a serial number instead?
  void Activity() { last_activity_ = Services::RoughTime(); }

  time_t LastActivity() const { return last_activity_; }

 protected:

  EventLoop *loop() const { return loop_; }

  bool WillAccept(int fd);

 private:

  int fd_;
  EventLoop *loop_;
  bool wants_erase_;
  CanDelete deletable_;
  time_t last_activity_;

  // Note that while you can set these low for test, they behave a
  // bit strangely when set low - for example, it is quite easy to
  // hit the limit even if the window is not 0. I'm guessing 1000
  // and 100 would be good numbers. Note EventLoop::kIdleTime below,
  // also.
  static const int kFDLimit = 1000;
  static const int kFDLimitWindow = 1;
};

class Listener : public FD {
 public:

  Listener(EventLoop *loop, int fd) : FD(loop, fd, NO_DELETE) {}

  bool WantsRead() const { return true; }

  void ReadIsAllowed() {
    int in = accept(fd(), NULL, NULL);
    CHECK_GE(in, 0);
    if (!WillAccept(in)) {
      static char sorry[] = "No free connections.\n";

      // we have to consume the result.
      ssize_t s = write(in, sorry, sizeof sorry);
      // but we don't care what it is...
      s = s;
      shutdown(in, SHUT_RDWR);
      close(in);
      return;
    }
    Accepted(in);
  }

  bool WantsWrite() const { return false; }

  void WriteIsAllowed() {
    DLOG(FATAL) << "WriteIsAllowed() called on a read-only Listener.";
  }

  virtual void Accepted(int fd) = 0;
};

class EventLoop {
 public:

  void Add(FD *fd) { fds_.push_back(fd); }

  void OneLoop() {
    fd_set readers, writers;
    int max = -1;

    memset(&readers, '\0', sizeof readers);
    memset(&writers, '\0', sizeof writers);
    for (std::deque<FD *>::const_iterator pfd = fds_.begin();
         pfd != fds_.end(); ++pfd) {
      FD *fd = *pfd;

      DCHECK(!fd->WantsErase());
      if (fd->WantsWrite())
        Set(fd->fd(), &writers, &max);
      if (fd->WantsRead())
        Set(fd->fd(), &readers, &max);
    }

    CHECK_GE(max, 0);

    int r = select(max+1, &readers, &writers, NULL, NULL);

    CHECK_GT(r, 0);

    Services::SetRoughTime();
    int n = 0;
    for (std::deque<FD *>::iterator pfd = fds_.begin(); pfd != fds_.end(); ) {
      FD *fd = *pfd;

      if (EraseCheck(&pfd))
        continue;

      if (FD_ISSET(fd->fd(), &writers)) {
        DCHECK(fd->WantsWrite());
        fd->WriteIsAllowed();
        fd->Activity();
        ++n;
      }

      if (EraseCheck(&pfd))
        continue;

      if (FD_ISSET(fd->fd(), &readers)) {
        DCHECK(fd->WantsRead());
        fd->ReadIsAllowed();
        fd->Activity();
        ++n;
      }

      if (EraseCheck(&pfd))
        continue;

      ++pfd;
    }
    CHECK_LE(n, r);
  }

  void Forever() {
    for ( ; ; )
      OneLoop();
  }

  void MaybeDropOne() {
    std::deque<FD *>::iterator drop = fds_.end();
    time_t oldest = Services::RoughTime() - kIdleTime;

    for (std::deque<FD *>::iterator pfd = fds_.begin();
         pfd != fds_.end(); ++pfd) {
      FD *fd = *pfd;

      if (fd->CanDrop() && fd->LastActivity() < oldest) {
        oldest = fd->LastActivity();
        drop = pfd;
      }
    }
    if (drop != fds_.end())
      (*drop)->Close();
  }

 private:

  bool EraseCheck(std::deque<FD *>::iterator *pfd) {
    if ((**pfd)->WantsErase()) {
      delete **pfd;
      *pfd = fds_.erase(*pfd);
      return true;
    }
    return false;
  }

  static void Set(int fd, fd_set *fdset, int *max) {
    DCHECK_GE(fd, 0);
    CHECK_LT((unsigned)fd, FD_SETSIZE);
    FD_SET(fd, fdset);
    if (fd > *max)
      *max = fd;
  }

  std::deque<FD *> fds_;
  time_t rough_time_;
  // This should probably be set to 2 for anything but test (or 1 or 0).
  // 2: everything gets a chance to speak.
  // 1: sometimes the clock will tick before some get a chance to speak.
  // 0: maybe no-one ever gets a chance to speak.
  static const time_t kIdleTime = 20;
};

FD::FD(EventLoop *loop, int fd, CanDelete deletable)
    : fd_(fd), loop_(loop), wants_erase_(false), deletable_(deletable) {
  DCHECK_GE(fd, 0);
  CHECK_LT((unsigned)fd, FD_SETSIZE);
  loop->Add(this);
  Activity();
}

bool FD::WillAccept(int fd) {
  if (fd >= kFDLimit - kFDLimitWindow)
    loop()->MaybeDropOne();
  return fd < kFDLimit;
}

class Server : public FD {
 public:

  Server(EventLoop *loop, int fd) : FD(loop, fd) {}

  bool WantsRead() const { return true; }

  void ReadIsAllowed() {
    byte buf[1024];

    ssize_t n = read(fd(), buf, sizeof buf);
    VLOG(5) << "read " << n << " bytes from " << fd();
    if (n <= 0) {
      Close();
      return;
    }
    rbuffer_.append(buf, (size_t)n);
    BytesRead(&rbuffer_);
  }

  // There are fresh bytes available in rbuffer.  It is the callee's
  // responsibility to remove consumed bytes from rbuffer. This will
  // NOT be called again until more data arrives from the network,
  // even if there are unconsumed bytes in rbuffer.
  virtual void BytesRead(bstring *rbuffer) = 0;

  bool WantsWrite() const { return !wbuffer_.empty(); }

  void WriteIsAllowed() {
    ssize_t n = write(fd(), wbuffer_.data(), wbuffer_.length());
    VLOG(5) << "wrote " << n << " bytes to " << fd();
    if (n <= 0) {
      Close();
      return;
    }
    wbuffer_.erase(0, n);
  }

  void Write(bstring str) { wbuffer_.append(str); }
  void Write(byte ch) { wbuffer_.push_back(ch); }

 private:

  bstring rbuffer_;
  bstring wbuffer_;
};

class CTLogManager {
 public:
  CTLogManager(FrontendSigner *signer)
      : signer_(signer) {}

  ~CTLogManager() { delete signer_; }

  enum LogReply {
    SIGNED_CERTIFICATE_TIMESTAMP,
    REJECT,
  };

  // Submit an entry and write a token, if the entry is accepted,
  // or an error otherwise.
  LogReply SubmitEntry(CertificateEntry::Type type, const bstring &data,
                       SignedCertificateTimestamp *sct, std::string *error) {
    SignedCertificateTimestamp local_sct;
    FrontendSigner::SubmitResult submit_result =
        signer_->QueueEntry(type, data, &local_sct);

    LogReply reply = REJECT;
    switch (submit_result) {
      case FrontendSigner::LOGGED:
      case FrontendSigner::PENDING:
      case FrontendSigner::NEW:
        sct->CopyFrom(local_sct);
        reply = SIGNED_CERTIFICATE_TIMESTAMP;
        break;
      default:
        error->assign(FrontendSigner::SubmitResultString(submit_result));
    }
    return reply;
  }
 private:
  FrontendSigner *signer_;
};

class CTServer : public Server {
 public:
  // Does not grab ownership of the manager.
  CTServer(EventLoop *loop, int fd, CTLogManager *manager)
      : Server(loop, fd),
        manager_(manager) {}

  static const ct::Version kVersion = ct::V0;
  static const ct::MessageFormat kFormat = ct::PROTOBUF;
  static const size_t kPacketPrefixLength = 3;
  static const size_t kMaxPacketLength = (1 << 24) - 1;

 private:
  void BytesRead(bstring *rbuffer) {
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

  void PacketRead(int version, int format, const bstring &data) {
    if (version != kVersion) {
      SendError(ServerError::BAD_VERSION);
      return;
    }

    if (format != kFormat) {
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

   std::string error;
   SignedCertificateTimestamp sct;
    CTLogManager::LogReply reply;
    // Since we successfully parsed the protobuf, apparently we know
    // the command but don't handle it.
    if (message.command() != ClientMessage::SUBMIT_BUNDLE &&
        message.command() != ClientMessage::SUBMIT_CA_BUNDLE) {
      SendError(ServerError::UNSUPPORTED_COMMAND);
      return;
    }
    if (message.command() == ClientMessage::SUBMIT_BUNDLE)
      reply = manager_->SubmitEntry(CertificateEntry::X509_ENTRY, data, &sct,
                                    &error);
    else
      reply = manager_->SubmitEntry(CertificateEntry::PRECERT_ENTRY, data, &sct,
                                    &error);

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

  void SendError(ServerError::ErrorCode error) {
    SendError(error, "");
  }

  void SendError(ServerError::ErrorCode error, const std::string &error_string) {
    ServerMessage message;
    message.set_response(ServerMessage::ERROR);
    message.mutable_error()->set_code(error);
    message.mutable_error()->set_error_message(error_string);

    SendMessage(message);
  }

  void SendSCTToken(const SignedCertificateTimestamp &sct) {
    ServerMessage message;
    message.set_response(ServerMessage::SIGNED_CERTIFICATE_TIMESTAMP);
    // Only send as little as needed (i.e., timestamp and signature).
    message.mutable_sct()->set_timestamp(sct.timestamp());
    message.mutable_sct()->mutable_signature()->CopyFrom(sct.signature());

    SendMessage(message);
  }

  void SendMessage(const ServerMessage &message) {
    std::string serialized_message;
    CHECK(message.SerializeToString(&serialized_message));
    // TODO(ekasper): remove the CHECK; it's temporary until we decide
    // how to split large messages.
    CHECK_LE(serialized_message.size(), kMaxPacketLength) <<
        "Attempted to send a message that exceeds maximum packet length.";

    Write(Serializer::SerializeUint(kVersion, 1));
    Write(Serializer::SerializeUint(kFormat, 1));
    Write(Serializer::SerializeUint(serialized_message.length(),
                                    kPacketPrefixLength));
    Write(serialized_message);
  }

  CTLogManager *manager_;
};

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

static bool InitServer(int *sock, int port, const char *ip, int type) {
  bool ret = false;
  struct sockaddr_in server;
  int s = -1;

  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_port = htons((unsigned short)port);
  if (ip == NULL)
    server.sin_addr.s_addr = INADDR_ANY;
  else
    memcpy(&server.sin_addr.s_addr, ip, 4);

  if (type == SOCK_STREAM)
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  else /* type == SOCK_DGRAM */
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s == -1)
    goto err;

  {
    int j = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &j, sizeof j);
  }

  if (bind(s, (struct sockaddr *)&server, sizeof(server)) == -1) {
    perror("bind");
    goto err;
  }
  /* Make it 128 for linux */
  if (type == SOCK_STREAM && listen(s, 128) == -1) goto err;
  *sock = s;
  ret = true;
err:
  if (!ret && s != -1) {
    shutdown(s, SHUT_RDWR);
    close(s);
  }
  return ret;
}

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  SSL_library_init();

  EVP_PKEY *pkey = NULL;

  FILE *fp = fopen(FLAGS_key.c_str(), "r");

  PCHECK(fp != static_cast<FILE*>(NULL)) << "Could not read private key file";
  // No password.
  PEM_read_PrivateKey(fp, &pkey, NULL, NULL);
  CHECK_NE(pkey, static_cast<EVP_PKEY*>(NULL)) <<
      FLAGS_key << " is not a valid PEM-encoded private key.";

  fclose(fp);

  int fd;
  CHECK(InitServer(&fd, FLAGS_port, NULL, SOCK_STREAM));

  EventLoop loop;

  CertChecker checker;
  CHECK(checker.LoadTrustedCertificateDir(FLAGS_trusted_cert_dir))
      << "Could not load CA certs from " << FLAGS_trusted_cert_dir;

  if (FLAGS_sqlite_db == "")
    CHECK_NE(FLAGS_cert_dir, FLAGS_tree_dir)
        << "Certificate directory and tree directory must differ";

  if ((FLAGS_cert_dir != "" || FLAGS_tree_dir != "") && FLAGS_sqlite_db != "") {
    std::cerr << "Choose either file or sqlite database, not both" << std::endl;
    exit(1);
  }

  Database *db;

  if (FLAGS_sqlite_db != "")
      db = new SQLiteDB(FLAGS_sqlite_db);
  else
      db = new FileDB(new FileStorage(FLAGS_cert_dir, FLAGS_cert_storage_depth),
                      new FileStorage(FLAGS_tree_dir,
                                      FLAGS_tree_storage_depth));

  FrontendSigner signer(db, new LogSigner(pkey),
                        new CertSubmissionHandler(&checker));

  CTLogManager manager(&signer);
  CTServerListener l(&loop, fd, &manager);
  LOG(INFO) << "Server listening on port " << FLAGS_port;
  loop.Forever();
}
