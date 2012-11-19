/* -*- indent-tabs-mode: nil -*- */

#include <deque>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <ldns/ldns.h>
// FIXME: debug
#include <ldns/host2str.h>
#include <ldns/wire2host.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "include/ct.h"
#include "log/cert_checker.h"
#include "log/cert_submission_handler.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/frontend_signer.h"
#include "log/frontend.h"
#include "log/log_lookup.h"
#include "log/log_signer.h"
#include "log/sqlite_db.h"
#include "log/tree_signer.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"
// FIXME: debug
#include "util/util.h"

DEFINE_int32(port, 0, "Server port");
DEFINE_int32(dnsport, 0, "Server DNS port");
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
static const bool dnsport_dummy = RegisterFlagValidator(&FLAGS_dnsport,
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

static const bool cert_dummy = RegisterFlagValidator(&FLAGS_trusted_cert_dir,
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

class RepeatedEvent {
 public:
  RepeatedEvent(time_t repeat_frequency_seconds)
      : frequency_(repeat_frequency_seconds),
        last_activity_(Services::RoughTime()) {}

 // The time when we should execute next.
  time_t Trigger() {
    return last_activity_ + frequency_;
  }

  virtual string Description() = 0;

  virtual void Execute() = 0;

  void Activity() {
    last_activity_ = Services::RoughTime();
  }
 private:
 time_t frequency_;
 time_t last_activity_;
};

class EventLoop {
 public:

  void Add(FD *fd) { fds_.push_back(fd); }

  void Add(RepeatedEvent *event) { events_.push_back(event); }

  // Returns remaining time until the next alarm.
  time_t ProcessRepeatedEvents() {
    if (events_.empty())
      return INT_MAX;
    Services::SetRoughTime();
    time_t now = Services::RoughTime();
    time_t earliest = INT_MAX;
    for (std::vector<RepeatedEvent *>::iterator it = events_.begin();
         it != events_.end(); ++it) {
      RepeatedEvent *event = *it;
      time_t trigger = event->Trigger();
      if (trigger <= now) {
        event->Execute();
        LOG(INFO) << "Executed " << event->Description() << " with a delay of "
                  << difftime(now, trigger) << " seconds";
        event->Activity();
        trigger = event->Trigger();
        CHECK_GT(trigger, now);
      }
      earliest = std::min(earliest, trigger);
    }
    CHECK_GT(earliest, 0);
    return earliest - now;
  }
  void OneLoop() {
    time_t select_timeout = ProcessRepeatedEvents();
    // Do not schedule any repeated events between now and the next
    // select - they will get ignored until select returns.
    CHECK_GT(select_timeout, 0);

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

    struct timeval tv;
    tv.tv_sec = select_timeout;
    tv.tv_usec = 0;

    int r = select(max+1, &readers, &writers, NULL, &tv);
    if (r == 0)
      return;

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
  std::vector<RepeatedEvent *> events_;
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
    char buf[1024];

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
  virtual void BytesRead(string *rbuffer) = 0;

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

  void Write(string str) { wbuffer_.append(str); }

 private:

  string rbuffer_;
  string wbuffer_;
};

class UDPServer : public FD {
 public:

  UDPServer(EventLoop *loop, int fd) : FD(loop, fd, NO_DELETE) {}

  bool WantsRead() const { return true; }

  void ReadIsAllowed() {
    char buf[2048];
    struct sockaddr_in sa;
    socklen_t sa_len = sizeof sa;

    ssize_t in = recvfrom(fd(), buf, sizeof buf, 0, (sockaddr *)&sa, &sa_len);
    CHECK_GE(in, 1);
    CHECK_EQ(sa_len, sizeof sa);
    LOG(INFO) << "UDP packet " << util::HexString(std::string(buf, in));
    PacketRead(sa, buf, in);
  }

  bool WantsWrite() const {
    return !write_queue_.empty();
  }

  void WriteIsAllowed() {
    CHECK(!write_queue_.empty());
    WBuffer wbuf = write_queue_.front();
    write_queue_.pop_front();
    ssize_t out = sendto(fd(), wbuf.packet.data(), wbuf.packet.length(), 0,
                         (const sockaddr *)&wbuf.sa, sizeof wbuf.sa);
    CHECK_NE(out, -1);
    CHECK_EQ((size_t)out, wbuf.packet.length());
  }

  // A packet has been read. It will not be re-presented if you do not
  // process it now.
  virtual void PacketRead(const sockaddr_in &from, const char *buf, size_t len)
    = 0;

  // Queue a packet for sending
  void QueuePacket(const sockaddr_in &to, const char *buf, size_t len) {
    WBuffer wbuf;
    wbuf.sa = to;
    wbuf.packet = string(buf, len);
    write_queue_.push_back(wbuf);
  }

private:
  struct WBuffer {
    sockaddr_in sa;
    string packet;
  };
  std::deque<WBuffer> write_queue_;
};

class UDPEchoServer : public UDPServer {
 public:

  UDPEchoServer(EventLoop *loop, int fd) : UDPServer(loop, fd) {}

  virtual void PacketRead(const sockaddr_in &from, const char *buf,
                          size_t len) {
    QueuePacket(from, buf, len);
  }
};

class CTUDPDNSServer : public UDPServer {
 public:

  CTUDPDNSServer(EventLoop *loop, int fd) : UDPServer(loop, fd) {}

  virtual void PacketRead(const sockaddr_in &from, const char *buf,
                          size_t len) {
    ldns_pkt *packet = NULL;

    ldns_status ret = ldns_wire2pkt(&packet, (const uint8_t *)buf, len);
    if (ret != LDNS_STATUS_OK) {
      LOG(INFO) << "Bad DNS packet";
      return;
    }
 
    ldns_pkt_print(stdout, packet);

    if (ldns_pkt_qr(packet) != 0) {
      LOG(INFO) << "Packet is not a query";
      return;
    }

    if (ldns_pkt_get_opcode(packet) != LDNS_PACKET_QUERY) {
      LOG(INFO) << "Packet has bad opcode";
      return;
    }

    ldns_rr_list *questions = ldns_pkt_question(packet);
    for (size_t n = 0; n < ldns_rr_list_rr_count(questions); ++n) {
      ldns_rr *question = ldns_rr_list_rr(questions, n);

      if (ldns_rr_get_type(question) != LDNS_RR_TYPE_TXT) {
        LOG(INFO) << "Question is not TXT";
        // FIXME(benl): set error response?
        continue;
      }

      LOG(INFO) << "Question is TXT";
    }
  }
};


class CTLogManager {
 public:
  CTLogManager(Frontend *frontend, TreeSigner *signer, LogLookup *lookup)
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
    return ss.str();
  }

  // Submit an entry and write a token, if the entry is accepted,
  // or an error otherwise.
  LogReply SubmitEntry(ct::LogEntryType type, const string &data,
                       SignedCertificateTimestamp *sct, string *error) {
    SignedCertificateTimestamp local_sct;
    Frontend::SubmitResult submit_result =
        frontend_->QueueEntry(type, data, &local_sct);

    LogReply reply = REJECT;
    switch (submit_result) {
      case Frontend::NEW:
      case Frontend::DUPLICATE:
        sct->CopyFrom(local_sct);
        reply = SIGNED_CERTIFICATE_TIMESTAMP;
        break;
      default:
        error->assign(Frontend::SubmitResultString(submit_result));
    }
    return reply;
  }

  LookupReply QueryAuditProof(uint64_t timestamp,
                              const std::string &certificate_hash,
                              ct::MerkleAuditProof *proof) {
    ct::MerkleAuditProof local_proof;
    LogLookup::LookupResult res =
        lookup_->CertificateAuditProof(timestamp, certificate_hash,
                                       &local_proof);
    if (res == LogLookup::OK) {
      proof->CopyFrom(local_proof);
      return MERKLE_AUDIT_PROOF;
    }
    CHECK_EQ(LogLookup::NOT_FOUND, res);
    return NOT_FOUND;
  }

  bool SignMerkleTree() {
    TreeSigner::UpdateResult res = signer_->UpdateTree();
    if (res != TreeSigner::OK) {
      LOG(ERROR) << "Tree update failed with return code " << res;
      return false;
    }
    time_t last_update = static_cast<time_t>(signer_->LastUpdateTime() / 1000);
    LOG(INFO) << "Tree successfully updated at " << ctime(&last_update);
    CHECK_EQ(LogLookup::UPDATE_OK, lookup_->Update());
    return true;
  }

 private:
  Frontend *frontend_;
  TreeSigner *signer_;
  LogLookup *lookup_;
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
        ClientLookup::MERKLE_AUDIT_PROOF_BY_TIMESTAMP_AND_HASH)) {
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
         manager_->QueryAuditProof(message.lookup().certificate_timestamp(),
                                   message.lookup().certificate_sha256_hash(),
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

  int dns_fd;
  CHECK(InitServer(&dns_fd, FLAGS_dnsport, NULL, SOCK_DGRAM));

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

  // Hmm, there is no EVP_PKEY_dup, so let's read the key again...
  EVP_PKEY *pkey2 = NULL;
  fp = fopen(FLAGS_key.c_str(), "r");

  PCHECK(fp != static_cast<FILE*>(NULL)) << "Could not read private key file";
  // No password.
  PEM_read_PrivateKey(fp, &pkey2, NULL, NULL);
  CHECK_NE(pkey, static_cast<EVP_PKEY*>(NULL)) <<
      FLAGS_key << " is not a valid PEM-encoded private key.";

  fclose(fp);

  CTLogManager manager(
      new Frontend(new CertSubmissionHandler(&checker),
                   new FrontendSigner(db, new LogSigner(pkey))),
      new TreeSigner(db, new LogSigner(pkey2)),
      new LogLookup(db));

  Services::SetRoughTime();
  TreeSigningEvent tree_event(FLAGS_tree_signing_frequency_seconds, &manager);
  FrontendLogEvent frontend_event(FLAGS_log_stats_frequency_seconds, &manager);
  loop.Add(&frontend_event);
  loop.Add(&tree_event);
  CTServerListener l(&loop, fd, &manager);
  CTUDPDNSServer dns(&loop, dns_fd);
  LOG(INFO) << "Server listening on port " << FLAGS_port;
  loop.Forever();
}
