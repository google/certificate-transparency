#include <assert.h>
#include <deque>
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

#include "../include/ct.h"
#include "../include/types.h"
#include "../log/cert_checker.h"
#include "../log/cert_submission_handler.h"
#include "../merkletree/LogDB.h"
#include "../merkletree/LogRecord.h"
#include "../merkletree/TreeLogger.h"

#define VV(x)

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
    assert(deletable_ == DELETE);
    if (wants_erase_)
	{
	std::cout << "Already closed " << fd() << std::endl;
	return;
	}
    std::cout << "Closing " << fd() << std::endl;
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
    assert(in >= 0);
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

  void WriteIsAllowed() { assert(false); }

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

      assert(!fd->WantsErase());
      if (fd->WantsWrite())
	Set(fd->fd(), &writers, &max);
      if (fd->WantsRead())
	Set(fd->fd(), &readers, &max);
    }

    assert(max >= 0);
    VV(std::cout << "Before select" << std::endl);
    int r = select(max+1, &readers, &writers, NULL, NULL);
    VV(std::cout << "After select" << std::endl);
    assert(r > 0);

    Services::SetRoughTime();
    int n = 0;
    for (std::deque<FD *>::iterator pfd = fds_.begin(); pfd != fds_.end(); ) {
      FD *fd = *pfd;

      if (EraseCheck(&pfd))
	  continue;

      if (FD_ISSET(fd->fd(), &writers)) {
	assert(fd->WantsWrite());
	fd->WriteIsAllowed();
	fd->Activity();
	++n;
      }

      if (EraseCheck(&pfd))
	  continue;

      if (FD_ISSET(fd->fd(), &readers))	{
	assert(fd->WantsRead());
	fd->ReadIsAllowed();
	fd->Activity();
	++n;
      }

      if (EraseCheck(&pfd))
	  continue;

      ++pfd;
    }
    assert(n <= r);
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
    assert(fd >= 0);
    assert((unsigned)fd < FD_SETSIZE);
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
  assert(fd >= 0);
  assert((unsigned)fd < FD_SETSIZE);
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
    VV(std::cout << "read " << n << " from " << fd() << std::endl);
    if (n <= 0)	{
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
    VV(std::cout << "wrote " << n << " to " << fd() << std::endl);
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

template <class Server> class ServerListener : public Listener {
public:

  ServerListener(EventLoop *loop, int fd) : Listener(loop, fd) {}

  void Accepted(int fd)	{
    std::cout << "Accepted " << fd << std::endl;
    new Server(loop(), fd);
  }
};

class CTLogManager {
 public:
  CTLogManager(TreeLogger *logger, size_t max_segment_size,
               time_t max_segment_delay)
      : logger_(logger),
        max_segment_size_(max_segment_size),
        max_segment_delay_(max_segment_delay) {
    // Else nothing ever gets logged.
    assert(max_segment_size_ > 0);
    assert(max_segment_delay_ > 0);
    segment_start_time_ = time(NULL);
  }

  ~CTLogManager() { delete logger_; }

  enum LogReply {
    INVALID_SUBMISSION,
    TOKEN,
    PROOF,
  };

  // Submit an entry and write a token, if the entry is pending,
  // or an audit proof, if it is already logged.
  LogReply SubmitEntry(LogEntry::LogEntryType type, const bstring &data,
                       bstring *result) {
    bstring key;
    LogDB::Status logreply = logger_->QueueEntry(type, data, &key);
    if (logreply == LogDB::REJECTED)
      return INVALID_SUBMISSION;

    assert(!key.empty());
    if (logreply == LogDB::NEW || logreply == LogDB::PENDING) {
      // Try to log it now.
      Manage();
    }

    AuditProof proof;
    LogDB::Status newreply = logger_->EntryAuditProof(key, &proof);
    // Consistency check.
    if (logreply == LogDB::LOGGED)
      assert(newreply == LogDB::LOGGED);

    if (newreply == LogDB::LOGGED) {
      if (result != NULL)
        result->assign(proof.Serialize());
      return PROOF;
    }
    assert(newreply == LogDB::PENDING);
    if (result != NULL)
      result->assign(key);
    return TOKEN;
  }

 private:
  void Manage() {
    time_t now = time(NULL);
    assert(now >= segment_start_time_);
    if (logger_->PendingLogSize() >= max_segment_size_ ||
        now - segment_start_time_ > max_segment_delay_) {
      logger_->LogSegment();
      segment_start_time_ = now;
    }
  }

  TreeLogger *logger_;
  // Max number of entries to log in one segment.
  size_t max_segment_size_;
  // Max time to wait before finalizing a segment. The manager will
  // start a new segment when the first of the two limits is met.
  time_t max_segment_delay_;
  time_t segment_start_time_;
};

class CTServer : public Server {
public:
  // Does not grab ownership of the manager.
  CTServer(EventLoop *loop, int fd, CTLogManager *manager)
  : Server(loop, fd),
    manager_(manager) {}

private:
  void BytesRead(bstring *rbuffer) {
    for ( ; ; ) {
      if (rbuffer->size() < 5)
	return;
      size_t length = DecodeLength(rbuffer->substr(2, 3));
      if (rbuffer->size() < length + 5)
	return;
      PacketRead((*rbuffer)[0], (*rbuffer)[1], rbuffer->substr(5, length));
      rbuffer->erase(0, length + 5);
    }
  }

  void PacketRead(byte version, byte command, const bstring &data) {
    if (version != 0) {
      SendError(ct::BAD_VERSION);
      return;
    }
    std::cout << "Command is " << (int)command << " data length "
	      << data.size() << std::endl;
    if (command != ct::UPLOAD_BUNDLE && command != ct::UPLOAD_CA_BUNDLE) {
      SendError(ct::BAD_COMMAND);
      return;
    }
    bstring result;
    CTLogManager::LogReply reply;
   // TODO globally: sort out this bstring/string mess.
    if (command == ct::UPLOAD_BUNDLE) {
      reply = manager_->SubmitEntry(LogEntry::X509_CHAIN_ENTRY, data, &result);
    } else {
      reply = manager_->SubmitEntry(LogEntry::PROTOCERT_CHAIN_ENTRY, data, &result);
    }
    switch(reply) {
      case CTLogManager::INVALID_SUBMISSION:
        SendError(ct::BAD_BUNDLE);
        break;
      case CTLogManager::TOKEN:
        assert(!result.empty());
        SendResponse(ct::SUBMITTED, result);
        break;
      case CTLogManager::PROOF:
        assert(!result.empty());
        SendResponse(ct::LOGGED, result);
        break;
      default:
        assert(false);
    }
  }

  size_t DecodeLength(const bstring &length) {
    size_t len = 0;
    for (size_t n = 0; n < length.size(); ++n)
      len = (len << 8) + length[n];
    return len;
  }

  void WriteLength(size_t length, size_t lengthOfLength) {
    assert(lengthOfLength <= sizeof length);
    assert(length < 1U << (lengthOfLength * 8));
    for ( ; lengthOfLength > 0; --lengthOfLength) {
      size_t b = length & (0xff << ((lengthOfLength - 1) * 8));
      Write(b >> ((lengthOfLength - 1) * 8));
    }
  }

  void SendError(ct::ServerError error) {
    Write(VERSION);
    Write(ct::ERROR);
    WriteLength(1, 3);
    Write(error);
  }

  void SendResponse(ct::ServerResponse code, const bstring &response) {
    Write(VERSION);
    Write(code);
    WriteLength(response.length(), 3);
    Write(response);
  }

  static const byte VERSION = 0;
  CTLogManager *manager_;
};

class CTServerListener : public Listener {
 public:
  CTServerListener(EventLoop *loop, int fd,
                   CTLogManager *manager) : Listener(loop, fd),
                                            manager_(manager) {}

  void Accepted(int fd)	{
    std::cout << "Accepted " << fd << std::endl;
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
  if (argc != 6) {
    std::cerr << argv[0] << " <port> <key> <size_limit> <time_limit> "
              << "<trusted_cert_dir>\n";
    exit(1);
  }

  int port = atoi(argv[1]);

  EVP_PKEY *pkey = NULL;

  FILE *fp = fopen(argv[2], "r");
  // No password.
  if (fp == NULL || PEM_read_PrivateKey(fp, &pkey, NULL, NULL) == NULL) {
    std::cerr << "Could not read private key.\n";
    exit(1);
  }

  fclose(fp);

  SSL_library_init();

  int fd;
  assert(InitServer(&fd, port, NULL, SOCK_STREAM));

  EventLoop loop;

  CertChecker checker;
  if(!checker.LoadTrustedCertificateDir(argv[5])) {
    std::cerr << "Could not load CA certs.\n";
    perror(argv[5]);
    exit(1);
  }

  TreeLogger logger(new MemoryDB(), new LogSigner(pkey),
                    new CertSubmissionHandler(&checker));
  size_t size_limit = atoi(argv[3]);
  time_t time_limit = atoi(argv[4]);
  CTLogManager manager(&logger, size_limit, time_limit);
  CTServerListener l(&loop, fd, &manager);
  loop.Forever();
}
