#include "client/client.h"

#include <arpa/inet.h>
#include <glog/logging.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __MACH__
// does not exist on MacOS
#define MSG_NOSIGNAL 0
#endif

using std::string;

Client::Client(const string& server, const string& port)
    : server_(server), port_(port), fd_(-1) {
}

Client::~Client() {
  Disconnect();
}

bool Client::Connect() {
  CHECK(!Connected());

  static const addrinfo server_addr_hints = {
    AI_ADDRCONFIG, /* ai_flags */
    AF_UNSPEC,     /* ai_family */
    SOCK_STREAM,   /* ai_socktype */
    IPPROTO_TCP    /* ai_protocol */
  };

  struct addrinfo* server_addr;

  const int ret = getaddrinfo(server_.c_str(), port_.c_str(),
                              &server_addr_hints, &server_addr);
  CHECK_EQ(0, ret) << "Invalid server address '" << server_
                   << "' and/or port '" << port_ << "': "
                   << gai_strerror(ret);

  bool is_connected = false;
  while (!is_connected && server_addr != NULL) {
    fd_ = socket(server_addr->ai_family,
                 server_addr->ai_socktype,
                 server_addr->ai_protocol);
    PCHECK(fd_ >= 0) << "Socket creation failed";

    if (connect(fd_, server_addr->ai_addr, server_addr->ai_addrlen) == 0) {
      is_connected = true;
    } else {
      server_addr = server_addr->ai_next; // Try next address
    }
  }
  freeaddrinfo(server_addr);

  if (!is_connected) {
    PLOG(ERROR) << "Connection to [" << server_ << "]:" << port_ << " failed";
    Disconnect();
    return false;
  }
  LOG(INFO) << "Connected to [" << server_ << "]:" << port_;
  return true;
}

bool Client::Connected() const {
  return fd_ > 0;
}

void Client::Disconnect() {
  if (fd_ > 0) {
    close(fd_);
    LOG(INFO) << "Disconnected from [" << server_ << "]:" << port_;
    fd_ = -1;
  }
}

bool Client::Write(const string& data) {
  CHECK(Connected());
  int n = send(fd_, data.data(), data.length(), MSG_NOSIGNAL);
  if (n <= 0) {
    PCHECK(errno == EPIPE) << "Send failed";
    LOG(ERROR) << "Remote server closed the connection.";
    Disconnect();
    return false;
  }

  CHECK_EQ(data.length(), (unsigned)n);

  VLOG(1) << "wrote " << data.length() << " bytes";
  return true;
}

bool Client::Read(size_t length, string* result) {
  CHECK(Connected());
  char* buf = new char[length];
  for (size_t offset = 0; offset < length;) {
    int n = recv(fd_, buf + offset, length - offset, MSG_NOSIGNAL);
    if (n <= 0) {
      PCHECK(errno == EPIPE) << "Read failed";
      LOG(ERROR) << "Remote server closed the connection.";
      Disconnect();
      delete[] buf;
      return false;
    }

    offset += n;
  }
  result->assign(string(buf, length));
  delete[] buf;
  VLOG(1) << "read " << length << " bytes";
  return true;
}
