#include "../include/ct.h"

#include <fstream>
#include <iostream>
#include <string>

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static const char nibble[] = "0123456789abcdef";

static std::string HexString(const bstring &data) {
  std::string ret;
  for (unsigned int i = 0; i < data.size(); ++i) {
    ret.push_back(nibble[(data[i] >> 4) & 0xf]);
    ret.push_back(nibble[data[i] & 0xf]);
  }
  return ret;
}

static void UnknownCommand(const std::string &cmd) {
  std::cerr << "Unknown command: " << cmd << '\n';
}

static void ReadAll(std::string *contents, std::ifstream &in) {
  for ( ; ; ) {
    char buf[1024];

    size_t n = in.read(buf, sizeof buf).gcount();
    assert(!in.fail() || in.eof());
    assert(n >= 0);
    contents->append(buf, n);
    if (in.eof())
      return;
  }
}

struct CTResponse {
  byte code;
  bstring data;
};

// Provisional packet format
// struct {
//  uint8 version;
//  uint8 command;
//  uint24 length;
//  opaque fragment[ClientCommand.length];
// } ClientCommand;

class CTClient {
public:
  CTClient(const char *server, unsigned port) {
    fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd_ < 0) {
      perror("Socket creation failed");
      exit(3);
    }

    static struct sockaddr_in server_socket;
    memset(&server_socket, 0, sizeof server_socket);
    server_socket.sin_family = AF_INET;
    server_socket.sin_port = htons(port);
    if (inet_aton(server, &server_socket.sin_addr) != 1) {
      std::cerr << "Can't parse server address: " << server << '.' << std::endl;
      exit(5);
    }

    std::cout << "Connecting to " << server << ':' << port << '.' << std::endl;
    int ret = connect(fd_, (struct sockaddr *)&server_socket,
		      sizeof server_socket);
    if (ret < 0) {
      close(fd_);
      perror("Connect failed");
      exit(4);
    }
  }
  // struct {
  //   opaque bundle[ClientCommand.length];
  // } ClientCommandUploadBundle;
  void UploadBundle(const std::string &bundle) {
    WriteCommand(ct::UPLOAD_BUNDLE);
    WriteData(bundle.data(), bundle.length());
    CTResponse response;
    ReadResponse(&response);
  }

private:
  void write(const void *buf, size_t length) const {
    for (size_t offset = 0; offset < length; ) {
      int n = ::write(fd_, ((char *)buf) + offset, length - offset);
      assert(n > 0);
      offset += n;
    }
  }

  void WriteByte(size_t b) const {
    char buf[1];
    buf[0] = b;
    write(buf, 1);
  }

  // Write MSB first.
  void WriteLength(size_t length, size_t length_of_length) const {
    assert(length_of_length <= sizeof length);
    assert(length < 1U << (length_of_length * 8));
    for ( ; length_of_length > 0; --length_of_length) {
      size_t b = length & (0xff << ((length_of_length - 1) * 8));
      WriteByte(b >> ((length_of_length - 1) * 8));
    }
  }

  void WriteCommand(ct::ClientCommand cmd) const {
    WriteByte(VERSION);
    WriteByte(cmd);
  }

  void WriteData(const void *buf, size_t length) const {
    WriteLength(length, 3);
    write(buf, length);
  }

  void read(void *buf, size_t length) const {
    for (size_t offset = 0; offset < length; ) {
      int n = ::read(fd_, ((char *)buf) + offset, length - offset);
      assert(n > 0);
      offset += n;
    }
  }

  byte ReadByte() const {
    byte buf[1];
    read(buf, 1);
    return buf[0];
  }

  size_t ReadLength(size_t length_of_length) const {
    byte buf[length_of_length];
    read(buf, length_of_length);
    size_t length = 0;
    for (size_t n = 0; n < length_of_length; ++n)
      length = (length << 8) + buf[n];
    return length;
  }

  void ReadString(bstring *dst, size_t length) const {
    byte buf[length];
    read(buf, length);
    dst->assign(buf, length);
  }

  void ReadResponse(CTResponse *response) {
    byte version = ReadByte();
    assert(version == VERSION);
    response->code = ReadByte();
    size_t length = ReadLength(3);
    ReadString(&response->data, length);
    std::cout << "Response code is " << (int)response->code << ", data length "
	      << length << std::endl;
    if (response->code == ct::SUBMITTED)
      std::cout << "Token is " << HexString(response->data) << std::endl;
  }

  int fd_;

  static const byte VERSION = 0;
};

static void Upload(int argc, const char **argv) {
  if (argc < 4) {
    std::cerr << argv[0] << " <file> <server> <port>\n";
    exit(2);
  }
  const char *file = argv[1];
  const char *server_name = argv[2];
  unsigned port = atoi(argv[3]);

  std::cout << "Uploading certificate bundle from " << file << '.' << std::endl;

  // FIXME: do some kind of sanity check on the contents?
  std::ifstream in(file);
  if (!in.is_open()) {
    perror(file);
    exit(6);
  }

  std::string contents;
  ReadAll(&contents, in);

  std::cout << file << " is " << contents.length() << " bytes." << std::endl;

  CTClient client(server_name, port);
  client.UploadBundle(contents);
}

int main(int argc, const char **argv) {
  if (argc < 2) {
    std::cerr << argv[0] << " <command> ...\n";
    return 1;
  }

  const std::string cmd(argv[1]);
  if (cmd == "upload")
    Upload(argc - 1, argv + 1);
  else
    UnknownCommand(cmd);
}
