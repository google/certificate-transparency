#include "cache.h"
#include "../include/ct.h"
#include "../util/ct_debug.h"
#include "../util/util.h"
#include "../merkletree/LogRecord.h"
#include "../merkletree/LogVerifier.h"

#include <fstream>
#include <iostream>
#include <string>

#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static void UnknownCommand(const std::string &cmd) {
  std::cerr << "Unknown command: " << cmd << '\n';
}

static void ReadAll(bstring *contents, std::ifstream &in) {
  for ( ; ; ) {
    unsigned char buf[1024];

    size_t n = in.read(reinterpret_cast<char*>(buf), sizeof buf).gcount();
    assert(!in.fail() || in.eof());
    assert(n >= 0);
    contents->append(buf, n);
    if (in.eof())
      return;
  }
}

// Really really dumb and temporary filestore methods.
static void WriteAllFiles(const std::vector<bstring> &files,
                          const char *dirname) {
  // Store current directory.
  char current_dir[1024];
  char *retbuf = getcwd(current_dir, sizeof current_dir);
  assert(retbuf != NULL);
  if (chdir(dirname) != 0) {
    perror(dirname);
    exit(1);
  }
  for (unsigned int i = 0; i < files.size(); ++i) {
    char filename[20];
    // 0000000000.tmp, 0000000001.tmp, etc.
    sprintf(filename, "%010d.tmp", i);
    FILE *out = fopen(filename, "wb");
    assert(out != NULL);
    fwrite(files[i].data(), 1, files[i].size(), out);
    fclose(out);
  }
  // Change back to working directory.
  int ret = chdir(current_dir);
  assert(ret == 0);
}

static std::vector<bstring> ReadAllFiles(const char *dirname) {
  std::vector<bstring> result;
  // Store current directory.
  char current_dir[1024];
  char *retbuf = getcwd(current_dir, sizeof current_dir);
  assert(retbuf != NULL);
  if (chdir(dirname) != 0) {
    perror(dirname);
    exit(1);
  }
  DIR *dir = opendir(".");
  if (dir == NULL) {
    perror(dirname);
    exit(1);
  }

  dirent *file = NULL;
  while ((file = readdir(dir)) != NULL) {
    if (file->d_type == DT_REG) {
      bstring contents;
      std::ifstream in(file->d_name);
      assert(in.is_open());
      ReadAll(&contents, in);
      result.push_back(contents);
      in.close();
    }
  }

  closedir(dir);
  int ret = chdir(current_dir);
  assert(ret == 0);
  return result;
}

// The proof extension in a superfluous certificate.
static const char kProofExtensionOID[] = "1.2.3.0";
// TODO: embedded proof, proto algorithm and proto signature could/should
// all be in the same extension. We keep them separate now for easier debugging.
// The proof.
static const char kEmbeddedProofExtensionOID[] = "1.2.3.1";
// The poison extension in the ProtoCert (critical).
static const char kPoisonExtensionOID[] = "1.2.3.2";
// The algorithm of the ProtoCert signature.
static const char kProtoAlgorExtensionOID[] = "1.2.3.3";
// The Protocert signature.
static const char kProtoSigExtensionOID[] = "1.2.3.4";

static ASN1_OBJECT *ExtensionObject(const char *oid) {
  unsigned char obj_buf[100];
  int obj_len = a2d_ASN1_OBJECT(obj_buf, sizeof obj_buf, oid,
                                sizeof oid - 1);
  assert(obj_len > 0);
  ASN1_OBJECT *obj = ASN1_OBJECT_create(0, obj_buf, obj_len, NULL, NULL);
  return obj;
}

static void AddExtension(X509 *cert, const char *oid, unsigned char *data,
                         int data_len, int critical) {
  ASN1_OBJECT *obj = ExtensionObject(oid);
  assert(obj != NULL);
  X509_EXTENSION *ext = X509_EXTENSION_new();
  assert(ext != NULL);
  int ret = X509_EXTENSION_set_object(ext, obj);
  assert(ret == 1);
  ret = X509_EXTENSION_set_critical(ext, critical);
  assert(ret == 1);
  if (data != NULL) {
    ASN1_OCTET_STRING *asn1_data = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(asn1_data, data, data_len);
    ret = X509_EXTENSION_set_data(ext, asn1_data);
    assert(ret == 1);
  }
  assert(cert != NULL);
  ret = X509_add_ext(cert, ext, -1);
  assert(ret == 1);
}

// Verify the proof on a log entry bundle.
static LogVerifier::VerifyResult
VerifyLogSegmentProof(const bstring &proofstring,
                      const bstring &bundle,
                      LogVerifier *verifier,
                      LogSegmentCheckpoint *checkpoint) {
  assert(verifier != NULL);
  AuditProof proof;
  bool serialized = proof.Deserialize(
      SegmentData::LOG_SEGMENT_TREE,
      *(reinterpret_cast<const std::string*>(&proofstring)));
  if (!serialized)
    return LogVerifier::INVALID_FORMAT;
  return verifier->VerifyLogSegmentAuditProof(proof,
                                              *(reinterpret_cast<const
                                                std::string*>(&bundle)),
                                              checkpoint);
}

// Verify the proof on a single leaf certificate.
static LogVerifier::VerifyResult
VerifyLogSegmentProof(const bstring &proofstring, X509 *cert,
                      LogVerifier *verifier,
                      LogSegmentCheckpoint *checkpoint) {
  unsigned char *buf = NULL;
  int cert_len = i2d_X509(cert, &buf);
  assert(cert_len > 0);
  bstring leaf(buf, cert_len);
  OPENSSL_free(buf);
  return VerifyLogSegmentProof(proofstring, leaf, verifier, checkpoint);
}

// A generic client.
class CTClient {
public:
  CTClient(const char *server, uint16_t port) {
    fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd_ < 0) {
      perror("Socket creation failed");
      exit(1);
    }

    static struct sockaddr_in server_socket;
    memset(&server_socket, 0, sizeof server_socket);
    server_socket.sin_family = AF_INET;
    server_socket.sin_port = htons(port);
    if (inet_aton(server, &server_socket.sin_addr) != 1) {
      std::cerr << "Can't parse server address: " << server << '.' << std::endl;
      exit(1);
    }

    std::cout << "Connecting to " << server << ':' << port << '.' << std::endl;
    int ret = connect(fd_, (struct sockaddr *)&server_socket,
		      sizeof server_socket);
    if (ret < 0) {
      close(fd_);
      perror("Connect failed");
      exit(1);
    }
  }

  ~CTClient() {
    close(fd_);
  }

 protected:
  int fd() const { return fd_; }

 private:
  int fd_;
}; // class CTClient

// A client for talking to the log server.
class LogClient : public CTClient {
 public:
  LogClient(const char *server, uint16_t port) : CTClient(server, port) {}
  // struct {
  //   opaque bundle[ClientCommand.length];
  // } ClientCommandUploadBundle;
  // Uploads the bundle; if the server returns a proof, writes the proof string
  // and returns true; else returns false.
  bool UploadBundle(const bstring &bundle, bstring *proof) {
    CTResponse response = Upload(bundle);
    bool ret = false;
    switch (response.code) {
      case ct::SUBMITTED:
        std::cout << "Token is " << util::HexString(response.data) << std::endl;
        break;
      case ct::LOGGED:
        std::cout << "Received proof " << util::HexString(response.data)
                  << std::endl;
        if (proof != NULL) {
          proof->assign(response.data);
          ret = true;
        }
        break;
      default:
        std::cout << "Unknown response code." << std::endl;
    }
    return ret;
  }

private:
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

  void write(const void *buf, size_t length) const {
    for (size_t offset = 0; offset < length; ) {
      int n = ::write(fd(), ((char *)buf) + offset, length - offset);
      assert(n > 0);
      offset += n;
    }
    DLOG_BINARY("send", buf, length);
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
    DLOG_UINT("length", length);
    char buf[length_of_length];
    for (size_t i = length_of_length; i > 0; --i) {
      size_t b = length & (0xff << ((i - 1) * 8));
      buf[length_of_length - i] = (b >> ((i - 1) * 8));
    }
    write(buf, length_of_length);
  }

  void WriteCommand(ct::ClientCommand cmd) const {
    DLOG_UINT("version", VERSION);
    WriteByte(VERSION);
    DLOG_UINT("command", cmd);
    WriteByte(cmd);
  }

  void WriteData(const void *buf, size_t length) const {
    WriteLength(length, 3);
    write(buf, length);
  }

  void read(void *buf, size_t length) const {
    for (size_t offset = 0; offset < length; ) {
      int n = ::read(fd(), ((char *)buf) + offset, length - offset);
      assert(n > 0);
      offset += n;
    }
    DLOG_BINARY("read", buf, length);
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
    DLOG_UINT("length", length);
    return length;
  }

  void ReadString(bstring *dst, size_t length) const {
    byte buf[length];
    read(buf, length);
    dst->assign(buf, length);
  }

  void ReadResponse(CTResponse *response) {
    DLOG_BEGIN_SERVER_MESSAGE;
    byte version = ReadByte();
    DLOG_UINT("version", version);
    assert(version == VERSION);
    response->code = ReadByte();
    DLOG_UINT("response code", response->code);
    size_t length = ReadLength(3);
    ReadString(&response->data, length);
    std::cout << "Response code is " << (int)response->code << ", data length "
	      << length << std::endl;
    DLOG_END_SERVER_MESSAGE;
  }

  CTResponse Upload(const bstring &bundle) {
    DLOG_BEGIN_CLIENT_MESSAGE;
    WriteCommand(ct::UPLOAD_BUNDLE);
    WriteData(bundle.data(), bundle.length());
    DLOG_END_CLIENT_MESSAGE;
    CTResponse response;
    ReadResponse(&response);
    return response;
  }
  static const byte VERSION = 0;
}; // class LogClient

class SSLClient : public CTClient {
 public:
  SSLClient(const char *server, uint16_t port) : CTClient(server, port),
                                                 ca_file_(NULL) {}

  SSLClient(const char *server, uint16_t port,
            const std::vector<bstring> &cache,
            const char *ca_file) : CTClient(server, port),
                                   cache_(cache),
                                   ca_file_(ca_file) {}

  std::vector<bstring> WriteCache() const {
    return cache_.WriteCache();
  }

  struct VerifyCallbackArgs {
    // The verifier for checking log proofs.
    LogVerifier *verifier;
    // The verification result.
    bool proof_verified;
    // The resulting checkpoint.
    LogSegmentCheckpoint checkpoint;
  };

#ifdef TLSEXT_AUTHZDATAFORMAT_audit_proof
  // The callback for verifying the proof in a TLS extension.
  static int AuditProofCallback(SSL *s, void *arg) {
    VerifyCallbackArgs *args = reinterpret_cast<VerifyCallbackArgs*>(arg);
    assert(args != NULL);
    // If we already received the proof in a superfluous cert, do nothing.
    if (args->proof_verified)
      return 1;

    LogVerifier *verifier = args->verifier;
    if (verifier == NULL) {
      std::cout << "No log server public key supplied. Dropping connection." <<
          std::endl;
      return 0;
    }

    SSL_SESSION *sess = SSL_get_session(s);
    // Get the leaf certificate.
    // TODO: verify proofs on entire certificate chains.
    X509 *cert = SSL_SESSION_get0_peer(sess);
    if (cert == NULL) {
      // VerifyCallback should have caught that already.
      std::cout << "No server certificate received. Dropping connection." <<
          std::endl;
      return 0;
    }

    // Get the proof.
    size_t proof_length;
    unsigned char *proof =
        SSL_SESSION_get_tlsext_server_authz_audit_proof(sess, &proof_length);
    if (proof == NULL) {
      std::cout << "No log proof received. Dropping connection." << std::endl;
      return 0;
    }

    std::cout << "Found an audit proof in the TLS extension, verifying...";

    bstring proofstring(proof, proof_length);
    LogVerifier::VerifyResult result =
        VerifyLogSegmentProof(proofstring, cert, verifier,
                              &args->checkpoint);

    if (result == LogVerifier::VERIFY_OK) {
      args->proof_verified = true;
      std::cout << "OK." << std::endl;
      return 1;
    } else {
      std::cout << LogVerifier::VerifyResultString(result) << std::endl;
      return 0;
    }
  }
#endif

// The callback for verifying the proof in a superfluous cert.
  static int VerifyCallback(X509_STORE_CTX *ctx, void *arg) {
    VerifyCallbackArgs *args = reinterpret_cast<VerifyCallbackArgs*>(arg);
    assert(args != NULL);
    LogVerifier *verifier = args->verifier;
    if (verifier == NULL) {
      std::cout << "No log server public key supplied. Dropping connection." <<
          std::endl;
      return 0;
    }

    if (ctx->cert == NULL) {
      std::cout << "No server certificate received. Dropping connection." <<
          std::endl;
      return 0;
    }

    // Make a local copy of the leaf cert so that we can modify it.
    X509 *leaf_cert = X509_dup(ctx->cert);
    bstring proofstring;
    // First, see if the cert has an embedded proof.
    ASN1_OBJECT *proof_obj = ExtensionObject(kEmbeddedProofExtensionOID);
    assert(proof_obj != NULL);
    int extension_index = X509_get_ext_by_OBJ(ctx->cert, proof_obj, -1);
    if (extension_index != -1) {
      std::cout << "Embedded proof extension found in certificate, "
                << "verifying...";
      X509_EXTENSION *ext = X509_get_ext(ctx->cert, extension_index);
      ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
      proofstring = bstring(ext_data->data, ext_data->length);
      // Delete the embedded proof extension.
      X509_delete_ext(leaf_cert, extension_index);
      unsigned char data[] = "poison";

      // Insert the poison extension.
      AddExtension(leaf_cert, kPoisonExtensionOID, data, 6, 1);
      // Find the protocert signature and plug it in.
      ASN1_OBJECT *algor_obj = ExtensionObject(kProtoAlgorExtensionOID);
      assert(algor_obj != NULL);
      extension_index = X509_get_ext_by_OBJ(leaf_cert, algor_obj, -1);
      assert(extension_index != -1);
      ext = X509_get_ext(leaf_cert, extension_index);
      ext_data = X509_EXTENSION_get_data(ext);

      if (leaf_cert->sig_alg != NULL)
        X509_ALGOR_free(leaf_cert->sig_alg);
      const unsigned char *algor_ptr = ext_data->data;
      leaf_cert->sig_alg = d2i_X509_ALGOR(NULL, &algor_ptr, ext_data->length);
      assert(leaf_cert->sig_alg != NULL);
      X509_delete_ext(leaf_cert, extension_index);

      ASN1_OBJECT *sig_obj = ExtensionObject(kProtoSigExtensionOID);
      assert(sig_obj != NULL);
      extension_index = X509_get_ext_by_OBJ(leaf_cert, sig_obj, -1);
      assert(extension_index != -1);
      ext = X509_get_ext(leaf_cert, extension_index);
      ext_data = X509_EXTENSION_get_data(ext);

      if (leaf_cert->signature != NULL)
        ASN1_BIT_STRING_free(leaf_cert->signature);
      const unsigned char *sig_ptr = ext_data->data;
      leaf_cert->signature =
          c2i_ASN1_BIT_STRING(NULL, &sig_ptr, ext_data->length);
      X509_delete_ext(leaf_cert, extension_index);

      // Let OpenSSL know that it needs to re-encode the cert.
      leaf_cert->cert_info->enc.modified = 1;

    } else {
      // Look for the proof in a superfluous cert.
      // TODO: is there an API call for accessing the bag of certs?
      STACK_OF(X509) *sk = ctx->untrusted;
      if (sk) {
        // Create the object by which we recognize the proof extension.
        ASN1_OBJECT *obj = ExtensionObject(kProofExtensionOID);
        assert(obj != NULL);
        for (int i = 0; i < sk_X509_num(sk); ++i) {
          X509 *cert = sk_X509_value(sk, i);
          int extension_index = X509_get_ext_by_OBJ(cert, obj, -1);
          if (extension_index != -1) {
            std::cout << "Proof extension found in certificate, verifying...";
            X509_EXTENSION *ext = X509_get_ext(cert, extension_index);
            ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
            proofstring = bstring(ext_data->data, ext_data->length);
          }
        }
      }
    }

    if (!proofstring.empty()) {
      // Only writes the checkpoint if verification succeeds.
      // Note: an optimized client could only verify the signature if it's
      // a checkpoint it hasn't seen before.
      LogVerifier::VerifyResult result =
          VerifyLogSegmentProof(proofstring, leaf_cert, verifier,
                                &args->checkpoint);
      if (result == LogVerifier::VERIFY_OK) {
        args->proof_verified = true;
        std::cout << "OK." << std::endl;
      } else {
        std::cout << LogVerifier::VerifyResultString(result) << std::endl;
      }
    }

    if (args->proof_verified)
      std::cout << "Log proof verified." << std::endl;
#ifndef TLSEXT_AUTHZDATAFORMAT_audit_proof
    // If we don't support the TLS extension, we fail here. Else we wait to see
    // if the extension callback finds a valid proof.
    else {
      std::cout << "No log proof received. Dropping connection." << std::endl;
      return 0;
    }
#endif
    int vfy = X509_verify_cert(ctx);
    if (vfy != 1) {
      // Echo a warning, but continue with connection.
      std::cout << "WARNING. Certificate verification failed." << std::endl;
    }
    return 1;
  }

  // Verification callbacks use this verifier for verifying log proofs.
  // Return true if a valid proof is found; false otherwise.
  bool SSLConnect(LogVerifier *verifier) {
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method());
    assert(ctx != NULL);
    // SSL_VERIFY_PEER makes the connection abort immediately
    // if verification fails.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // Set trusted CA certs.
    int ret;
    if (ca_file_ != NULL) {
      ret = SSL_CTX_load_verify_locations(ctx, ca_file_, NULL);
      assert(ret == 1);
    }
    VerifyCallbackArgs args;
    args.verifier = verifier;
    args.proof_verified = false;
    // The verify callback gets called before the audit proof callback.
    SSL_CTX_set_cert_verify_callback(ctx, &VerifyCallback, &args);
#ifdef TLSEXT_AUTHZDATAFORMAT_audit_proof
    SSL_CTX_set_tlsext_server_authz_audit_proof_cb(ctx, &AuditProofCallback);
    SSL_CTX_set_tlsext_server_authz_audit_proof_cb_arg(ctx, &args);
#endif
    SSL *ssl = SSL_new(ctx);
    assert(ssl != NULL);
    BIO *bio = BIO_new_socket(fd(), BIO_NOCLOSE);
    assert(bio != NULL);
    // Takes ownership of bio.
    SSL_set_bio(ssl, bio, bio);
    ret = SSL_connect(ssl);
    // TODO: check and report certificate verification errors.
    if (ret == 1)
      std::cout << "Connected." << std::endl;
    else
      std::cout << "Connection failed." << std::endl;
    // Cache the checkpoint.
    if (args.proof_verified) {
      switch(cache_.Insert(args.checkpoint)) {
        case LogSegmentCheckpointCache::NEW:
          std::cout << "Cached new checkpoint." << std::endl;
          break;
        case LogSegmentCheckpointCache::CACHED:
          std::cout << "Checkpoint already in cache." << std::endl;
          break;
        case LogSegmentCheckpointCache::MISMATCH:
          std::cout << "ERROR: checkpoint mismatch!" << std::endl;
          break;
        default:
          assert(false);
      }
    }

    // TODO: if the server closes the socket then the client cannot
    // connect again. Make sure we only allow SSLConnect() once.
    if (ssl) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
    }
    SSL_CTX_free(ctx);
    return args.proof_verified;
  }

 private:
  LogSegmentCheckpointCache cache_;
  const char *ca_file_;
}; // class SSLCLient

static void UploadHelp() {
    std::cerr << "upload <file> <server> <port> [-server_key key_file] " <<
        "[-out proof_file]" << std::endl;
}

static void Upload(int argc, const char **argv) {
  if (argc < 4) {
    UploadHelp();
    exit(1);
  }
  const char *file = argv[1];
  const char *server_name = argv[2];
  uint16_t port = atoi(argv[3]);

  const char *key_file = NULL;
  const char *proof_file = NULL;

  EVP_PKEY *pkey = NULL;
  FILE *out = NULL;

  argc -= 4;
  argv += 4;

  while (argc >= 2) {
    if (strcmp(argv[0], "-server_key") == 0) {
      if (key_file != NULL) {
        UploadHelp();
        exit(1);
      }
      key_file = argv[1];
      argc -= 2;
      argv += 2;
    } else if (strcmp(argv[0], "-out") == 0) {
      if (proof_file != NULL) {
        UploadHelp();
        exit(1);
      }
      proof_file = argv[1];
      argc -= 2;
      argv += 2;
    } else {
      UploadHelp();
      exit(1);
    }
  }

  if (argc) {
    UploadHelp();
    exit(1);
  }

  std::ifstream in(file);
  if (!in.is_open()) {
    perror(file);
    exit(1);
  }

  if (key_file != NULL) {
    FILE *fp = fopen(key_file, "r");
    if (fp == NULL) {
      perror(key_file);
      exit(1);
    }
    if (PEM_read_PUBKEY(fp, &pkey, NULL, NULL) == NULL) {
      std::cerr << "Could not read log server public key" << std::endl;
      exit(1);
    }
    fclose(fp);
  }

  if (proof_file != NULL) {
    out = fopen(proof_file, "wb");
    if (out == NULL) {
      perror(proof_file);
      exit(1);
    }
  }

  std::cout << "Uploading certificate bundle from " << file << '.' << std::endl;

  // Assume for now that we get a single leaf cert.
  // TODO: properly encode the submission with length prefixes,
  // to match the spec.
  bstring contents;
  ReadAll(&contents, in);
  std::cout << file << " is " << contents.length() << " bytes." << std::endl;

  X509 *cert = NULL;
  const unsigned char *dataptr = contents.data();
  if ((cert = d2i_X509(&cert, &dataptr, contents.size())) == NULL) {
    std::cerr << "Input is not a valid DER-encoded certificate." << std::endl;
    exit(1);
  }
  X509_free(cert);

  LogClient client(server_name, port);
  bstring proof;
  if(!client.UploadBundle(contents, &proof)) {
    std::cout << "No log proof received. Try again later." << std::endl;
    if (out != NULL) {
      fclose(out);
      remove(proof_file);
    }
    if (pkey != NULL)
      EVP_PKEY_free(pkey);
  } else {
    if (pkey == NULL) {
      std::cout << "WARNING: no log server key supplied. Cannot verify proof."
                << std::endl;
    } else {
      LogVerifier verifier(pkey);
      LogVerifier::VerifyResult result = VerifyLogSegmentProof(proof, contents,
                                                               &verifier, NULL);
      if (result == LogVerifier::VERIFY_OK)
        std::cout << "Proof verified." << std::endl;
      else
        std::cout << "ERROR: " << LogVerifier::VerifyResultString(result)
                  << std::endl;
    }
    if (out != NULL) {
      fwrite(proof.data(), 1, proof.size(), out);
      fclose(out);
      std::cout << "Wrote proof to " << proof_file << std::endl;
    }
  }
}

// FIXME: fix all the memory leaks in this code.
static void MakeCert(int argc, const char **argv) {
  if (argc != 3) {
    std::cerr << argv[0] << " <input proof> <output certificate>\n";
    exit(1);
  }
  const char *proof_file = argv[1];
  const char *cert_file = argv[2];

  int proof_fd = open(proof_file, O_RDONLY);
  assert(proof_fd >= 0);
  unsigned char proof[2048];
  ssize_t proof_len = read(proof_fd, proof, sizeof proof);
  assert(proof_len >= 0);
  assert(proof_len < (ssize_t)sizeof proof);

  int cert_fd = open(cert_file, O_CREAT | O_TRUNC | O_WRONLY, 0666);
  assert(cert_fd >= 0);
  BIO *out = BIO_new_fd(cert_fd, BIO_CLOSE);

  X509 *x = X509_new();

  // X509v3 (== 2)
  X509_set_version(x, 2);

  // Random 128 bit serial number
  BIGNUM *serial = BN_new();
  BN_rand(serial, 128, 0, 0);
  BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(x));
  BN_free(serial);

  // Set signature algorithm
  // FIXME: is there an opaque way to get the algorithm structure?
  x->cert_info->signature->algorithm = OBJ_nid2obj(NID_sha1WithRSAEncryption);
  x->cert_info->signature->parameter = NULL;

  // Set the start date to now
  X509_gmtime_adj(X509_get_notBefore(x), 0);
  // End date to now + 1 second
  X509_gmtime_adj(X509_get_notAfter(x), 1);

  // Create the issuer name
  X509_NAME *issuer = X509_NAME_new();
  X509_NAME_add_entry_by_NID(issuer, NID_commonName, V_ASN1_PRINTABLESTRING,
			     const_cast<unsigned char *>(
			       reinterpret_cast<const unsigned char *>("Test")),
			     4, 0, -1);
  X509_set_issuer_name(x, issuer);

  // Create the subject name
  X509_NAME *subject = X509_NAME_new();
  X509_NAME_add_entry_by_NID(subject, NID_commonName, V_ASN1_PRINTABLESTRING,
			     const_cast<unsigned char *>(
			       reinterpret_cast<const unsigned char *>("tseT")),
			     4, 0, -1);
  X509_set_subject_name(x, subject);

  // Public key
  RSA *rsa = RSA_new();
  static const unsigned char bits[1] = { 3 };
  rsa->n = BN_bin2bn(bits, 1, NULL);
  rsa->e = BN_bin2bn(bits, 1, NULL);
  EVP_PKEY *evp_pkey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(evp_pkey, rsa);
  X509_PUBKEY_set(&X509_get_X509_PUBKEY(x) , evp_pkey);

  // And finally, the proof in an extension
  AddExtension(x, kProofExtensionOID, proof, proof_len, 1);

  int i = i2d_X509_bio(out, x);
  assert(i != 0);

  BIO_free(out);
}

// Input: a certificate request (in PEM format).
// Output: a signed proto-certificate (in DER format).
// The protocert is formatted like a regular X509v3 certificate,
// except it is signed with the protocert signing certificate,
// and contains two additional extensions:
// - A critical "Certificate Transparency" poison extension to indicate
//   its proto status.
// - An Authority issuer/keyid extension that specifies the signing key of the
//   final certificate (rather than the protocert signing key)
// The conf file MUST contain a "proto" section with all desired extensions,
// as well as the following lines:
// authorityKeyIdentifier=keyid:always,issuer:always
// 1.2.3.4=critical,ASN1:UTF8String:poison
// TODO: define a "real" poison extension.
static void MakeProtoCert(int argc, const char **argv) {
  if (argc != 8) {
    std::cerr << argv[0] << " <input request> <output signed ProtoCert> "
              << "<CA protocert signing cert> <CA protocert signing key> "
              << "<CA protocert signing key password> <CA cert> <conf file> \n";
    exit(1);
  }
  const char *req_file = argv[1];
  const char *out_file = argv[2];
  const char *ca_protocert_file = argv[3];
  const char *ca_protokey_file = argv[4];
  const char *password = argv[5];
  const char *ca_cert_file = argv[6];
  const char *conf_file = argv[7];

  const char kSection[] = "proto";

  BIO *req_bio = BIO_new(BIO_s_file());
  assert(req_bio != NULL);
  int ret = BIO_read_filename(req_bio, req_file);
  assert(ret == 1);
  X509_REQ *req = PEM_read_bio_X509_REQ(req_bio, NULL, NULL, NULL);
  assert(req != NULL);
  BIO_free(req_bio);

  BIO *ca_protocert_bio = BIO_new(BIO_s_file());
  assert(ca_protocert_bio != NULL);
  ret = BIO_read_filename(ca_protocert_bio, ca_protocert_file);
  assert(ret == 1);
  X509 *ca_protocert = PEM_read_bio_X509(ca_protocert_bio, NULL, NULL, NULL);
  assert(ca_protocert != NULL);
  BIO_free(ca_protocert_bio);

  BIO *ca_protokey_bio = BIO_new(BIO_s_file());
  assert(ca_protokey_bio != NULL);
  ret = BIO_read_filename(ca_protokey_bio, ca_protokey_file);
  assert(ret == 1);
  EVP_PKEY *ca_protokey = PEM_read_bio_PrivateKey(ca_protokey_bio, NULL, NULL,
                                                  const_cast<char*>(password));
  assert(ca_protokey != NULL);
  BIO_free(ca_protokey_bio);

  BIO *ca_cert_bio = BIO_new(BIO_s_file());
  assert(ca_cert_bio != NULL);
  ret = BIO_read_filename(ca_cert_bio, ca_cert_file);
  assert(ret == 1);
  X509 *ca_cert = PEM_read_bio_X509(ca_cert_bio, NULL, NULL, NULL);
  assert(ca_cert != NULL);
  BIO_free(ca_cert_bio);

  //
  // The following code mostly follows the logic of 'openssl x509 -req'
  // as implemented in openssl/apps/x509.c
  //

  X509 *proto = X509_new();
  // Set the version to v3.
  ret = X509_set_version(proto, 2);
  assert(ret == 1);

  // Random 128-bit serial number.
  // TODO: take a serial file as input.
  BIGNUM *serial = BN_new();
  BN_rand(serial, 128, 0, 0);
  BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(proto));
  BN_free(serial);

  // Subject name.
  X509_NAME *subject = X509_REQ_get_subject_name(req);
  assert(subject != NULL);
  ret = X509_set_subject_name(proto, subject);
  assert(ret == 1);

  // Subject public key.
  EVP_PKEY *pkey = X509_REQ_get_pubkey(req);
  assert(pkey != NULL);
  // Verify the signature on the request.
  ret = X509_REQ_verify(req, pkey);
  assert(ret == 1);
  X509_set_pubkey(proto, pkey);
  assert(ret == 1);
  // X509_REQ_get_pubkey increases the reference count, so decrease it again.
  EVP_PKEY_free(pkey);

  // The eventual issuer shall be the CA cert.
  X509_NAME *issuer = X509_get_subject_name(ca_cert);
  assert(issuer != NULL);
  // Check that this is the same as the issuer of the CA protocert.
  X509_NAME *proto_issuer = X509_get_issuer_name(ca_protocert);
  assert(proto_issuer != NULL);
  ret = X509_NAME_cmp(issuer, proto_issuer);
  assert(ret == 0);
  X509_set_issuer_name(proto, issuer);

  // Validity.
  // Set the start date to now.
  X509_gmtime_adj(X509_get_notBefore(proto), 0);
  // End date to now + 1 year.
  // TODO: this, too, should be configurable.
  X509_time_adj_ex(X509_get_notAfter(proto), 365, 0, NULL);

  // Add the extensions.
  X509V3_CTX ctx;
  CONF *extconf = NCONF_new(NULL);
  long errorline = -1;
  ret = NCONF_load(extconf, conf_file, &errorline);
  assert(ret == 1);

  X509V3_set_ctx(&ctx, ca_cert, proto, NULL, NULL, 0);
  X509V3_set_nconf(&ctx, extconf);
  ret = X509V3_EXT_add_nconf(extconf, &ctx, const_cast<char*>(kSection),
                              proto);
  assert(ret == 1);

  // Sign.
  ret = X509_sign(proto, ca_protokey, NULL);
  assert(ret > 0);

  int out_fd = open(out_file, O_CREAT | O_TRUNC | O_WRONLY, 0666);
  assert(out_fd >= 0);
  BIO *out_bio = BIO_new_fd(out_fd, BIO_CLOSE);
  ret = i2d_X509_bio(out_bio, proto);
  assert(ret > 0);
  BIO_free(out_bio);

  X509_REQ_free(req);
  X509_free(proto);
  X509_free(ca_protocert);
  X509_free(ca_cert);
  EVP_PKEY_free(ca_protokey);
  NCONF_free(extconf);
}

// Input: a protocert (in DER format) and a proof (raw binary).
// Output: a signed certificate (in PEM format).
static void ProtoCertToCert(int argc, const char **argv) {
  if (argc != 6) {
    std::cerr << argv[0] << " <protocert> <proof> <output cert> <CA key> "
              << "<CA key password>\n";
    exit(1);
  }
  const char *protocert_file = argv[1];
  const char *proof_file = argv[2];
  const char *out_file = argv[3];
  const char *ca_key_file = argv[4];
  const char *password = argv[5];

  BIO *protocert_bio = BIO_new(BIO_s_file());
  assert(protocert_bio != NULL);
  int ret = BIO_read_filename(protocert_bio, protocert_file);
  assert(ret == 1);
  X509 *protocert = d2i_X509_bio(protocert_bio, NULL);
  assert(protocert != NULL);
  BIO_free(protocert_bio);

  int proof_fd = open(proof_file, O_RDONLY);
  assert(proof_fd >= 0);
  unsigned char proof[2048];
  ssize_t proof_len = read(proof_fd, proof, sizeof proof);
  assert(proof_len >= 0);
  assert(proof_len < (ssize_t)sizeof proof);

  // TODO: verify the proof.

  BIO *ca_key_bio = BIO_new(BIO_s_file());
  assert(ca_key_bio != NULL);
  ret = BIO_read_filename(ca_key_bio, ca_key_file);
  assert(ret == 1);
  EVP_PKEY *ca_key = PEM_read_bio_PrivateKey(ca_key_bio, NULL, NULL,
                                             const_cast<char*>(password));
  assert(ca_key != NULL);
  BIO_free(ca_key_bio);

  // Remove the poison extension.
  ASN1_OBJECT *poison = ExtensionObject(kPoisonExtensionOID);
  assert(poison != NULL);
  int extension_index = X509_get_ext_by_OBJ(protocert, poison, -1);
  assert(extension_index != -1);
  X509_delete_ext(protocert, extension_index);

  // Add the proof extension.
  AddExtension(protocert, kEmbeddedProofExtensionOID, proof, proof_len, 0);

  // Move the protocert algorithm and signature to a new extension.
  unsigned char *algor_buf = NULL;
  int algor_length = i2d_X509_ALGOR(protocert->sig_alg, &algor_buf);
  assert(algor_length > 0);
  AddExtension(protocert, kProtoAlgorExtensionOID, algor_buf, algor_length, 0);
  OPENSSL_free(algor_buf);

  int sig_length = i2c_ASN1_BIT_STRING(protocert->signature, NULL);
  assert(sig_length > 0);
  unsigned char *sig_buf = new unsigned char[sig_length];
  // i2c modifies sig_buf
  unsigned char *sig_buf_save = sig_buf;
  ret = i2c_ASN1_BIT_STRING(protocert->signature, &sig_buf);
  assert(ret > 0);
  AddExtension(protocert, kProtoSigExtensionOID, sig_buf_save, sig_length, 0);
  delete[] sig_buf_save;

  // Sign with the CA cert.
  ret = X509_sign(protocert, ca_key, NULL);
  assert(ret > 0);

  int out_fd = open(out_file, O_CREAT | O_TRUNC | O_WRONLY, 0666);
  assert(out_fd >= 0);
  BIO *out_bio = BIO_new_fd(out_fd, BIO_CLOSE);
  ret = PEM_write_bio_X509(out_bio, protocert);
  assert(ret > 0);
  BIO_free(out_bio);

  X509_free(protocert);
  EVP_PKEY_free(ca_key);
}

// The number currently assigned in OpenSSL for
// TLSEXT_AUTHDATAFORMAT_audit_proof.
static const unsigned char kAuditProofFormat = 182;

// Wrap the proof in a server_authz format, so that we can feed it to OpenSSL.
static void ProofToAuthz(int argc, const char **argv) {
  if (argc != 3) {
    std::cerr << argv[0] << " <input proof> <output authz>\n";
    exit(1);
  }
  const char *proof_in_file = argv[1];
  const char *authz_out_file = argv[2];

  std::ifstream proof_in(proof_in_file, std::ios::in|std::ios::binary);
  if (!proof_in.good()) {
    perror(proof_in_file);
    exit(1);
  }

  std::ofstream authz_out(authz_out_file, std::ios::out|std::ios::binary);
  if (!authz_out.good()) {
    perror(authz_out_file);
    exit(1);
  }

  // TLSEXT_AUTHDATAFORMAT_audit_proof
  authz_out << kAuditProofFormat;

  // Count proof length.
  proof_in.seekg(0, std::ios::end);
  int proof_length = proof_in.tellg();
  // Rewind.
  proof_in.seekg(0, std::ios::beg);

  // Write the length.
  authz_out << static_cast<unsigned char>(proof_length >> 8)
            << static_cast<unsigned char>(proof_length);

  // Now write the proof.
  char *buf = new char[proof_length];
  proof_in.read(buf, proof_length);
  assert(proof_in.gcount() == proof_length);
  authz_out.write(buf, proof_length);
  assert(!authz_out.bad());

  delete[] buf;
  proof_in.close();
  authz_out.close();
}

static void ConnectHelp() {
  std::cerr << "connect <server> <port> [-log_server_key key_file] "
            << "[-cache cache_dir] [-ca_file ca_file]" << std::endl;
}

static bool Connect(int argc, const char **argv) {
  if (argc < 3) {
    ConnectHelp();
    exit(1);
  }
  const char *server_name = argv[1];
  unsigned port = atoi(argv[2]);

  const char *key_file = NULL;
  const char *cache_dir = NULL;
  const char *ca_file = NULL;

  EVP_PKEY *pkey = NULL;

  argc -= 3;
  argv += 3;

  while (argc >= 2) {
    if (strcmp(argv[0], "-log_server_key") == 0) {
      if (key_file != NULL) {
        ConnectHelp();
        exit(1);
      }
      key_file = argv[1];
      argc -= 2;
      argv += 2;
    } else if (strcmp(argv[0], "-cache") == 0) {
      if (cache_dir != NULL) {
        ConnectHelp();
        exit(1);
      }
      cache_dir = argv[1];
      argc -= 2;
      argv += 2;
    } else if (strcmp(argv[0], "-ca_file") == 0) {
      if (ca_file != NULL) {
        ConnectHelp();
        exit(1);
      }
      ca_file = argv[1];
      argc -= 2;
      argv += 2;
    } else {
      ConnectHelp();
      exit(1);
    }
  }

  if (argc) {
    ConnectHelp();
    exit(1);
  }

  if (key_file != NULL) {
    FILE *fp = fopen(key_file, "r");
    if (fp == NULL) {
      perror(key_file);
      exit(1);
    }
    if (PEM_read_PUBKEY(fp, &pkey, NULL, NULL) == NULL) {
      std::cerr << "Could not read log server public key" << std::endl;
      exit(1);
    }
    fclose(fp);
  }

  LogVerifier *verifier = NULL;
  if (pkey != NULL)
    verifier = new LogVerifier(pkey);
  std::vector<bstring> cache;
  if (cache_dir != NULL) {
    std::cout << "Reading cache...";
    cache = ReadAllFiles(cache_dir);
    std::cout << "OK." << std::endl;
  }
  SSLClient client(server_name, port, cache, ca_file);
  bool proof_verified = client.SSLConnect(verifier);
  if (cache_dir != NULL) {
    std::cout << "Writing cache...";
    cache = client.WriteCache();
    WriteAllFiles(cache, cache_dir);
    std::cout << "OK." << std::endl;
  }
  delete verifier;
  return proof_verified;
}

static void UsageHelp(const std::string &cmd) {
  std::cerr << cmd <<  " [-debug [-debug_out file]] <command> ..."
            << std::endl;
}

// Return value:
// 0: success
// 1: system error/invalid argument/etc
// 2: proof verification error (for Connect())
int main(int argc, const char **argv) {
  const std::string main_command(argv[0]);
  if (argc < 2) {
    UsageHelp(main_command);
    return 1;
  }

  ++argv;
  --argc;

  if (strcmp(argv[0], "-debug") == 0) {
    ++argv;
    --argc;
    if (argc == 0) {
      UsageHelp(main_command);
      return 1;
    }
    if (strcmp(argv[0], "-debug_out") == 0) {
      ++argv;
      --argc;
      if (argc == 0) {
        UsageHelp(main_command);
        return 1;
      }
      InitDebug(argv[0]);
      ++argv;
      --argc;
    } else {
      InitDebug();
    }
  }

  if (argc < 2) {
    UsageHelp(main_command);
    return 1;
  }

  SSL_library_init();

  const std::string cmd(argv[0]);

  if (cmd == "connect") {
    if(!Connect(argc, argv))
      // Connection succeeded but the server presented no valid proof.
      return 2;
    return 0;
  }

  if (cmd == "upload")
    Upload(argc, argv);
  else if (cmd == "certificate")
    MakeCert(argc, argv);
  else if (cmd == "protocert") {
    MakeProtoCert(argc, argv);
  } else if (cmd == "sign") {
    ProtoCertToCert(argc, argv);
  } else if (cmd == "authz") {
    ProofToAuthz(argc, argv);
  } else {
    UnknownCommand(cmd);
    UsageHelp(main_command);
  }
}
