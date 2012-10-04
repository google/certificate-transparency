#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>
#include "types.h"

// Socket creation for client connections.
class Client {
public:
  Client(const std::string &server, uint16_t port);

  ~Client();

  // Create a TCP socket and attempt to connect to server:port.
  // The Connect()-Disconnect() sequence can be called repeatedly.
  bool Connect();

  int fd() const { return fd_; }

  // The remote end may have closed the socket, in which
  // case this will still return true, but the next read/write
  // will fail and disconnect.
  bool Connected() const;

  void Disconnect();

  bool Write(const bstring &data);

  bool Read(size_t length, bstring *result);

 private:
  const std::string server_;
  const uint16_t port_;
  int fd_;
};
#endif
