#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cache.h"
#include "cert.h"
#include "cert_submission_handler.h"
#include "ct.h"
#include "ct.pb.h"
#include "ct_debug.h"
#include "log_signer.h"
#include "log_verifier.h"
#include "merkle_verifier.h"
#include "serial_hasher.h"
#include "serializer.h"
#include "util.h"
#include "types.h"

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
      bool read_success = util::ReadBinaryFile(file->d_name, &contents);
      assert(read_success);
      result.push_back(contents);
    }
  }

  closedir(dir);
  int ret = chdir(current_dir);
  assert(ret == 0);
  return result;
}

static void AddExtension(X509 *cert, const char *oid, unsigned char *data,
                         int data_len, int critical) {
  ASN1_OBJECT *obj = Cert::ExtensionObject(oid);
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


static LogVerifier::VerifyResult
VerifyLogSignature(const bstring &token, const CertChain &cert_chain,
                   LogVerifier *verifier, SignedCertificateTimestamp *sct) {
  CertificateEntry *entry = CertSubmissionHandler::X509ChainToEntry(cert_chain);
  if (entry == NULL)
    return LogVerifier::INVALID_FORMAT;

  SignedCertificateTimestamp local_sct;
  if (Deserializer::DeserializeSCTToken(token, &local_sct) != Deserializer::OK)
    return LogVerifier::INVALID_FORMAT;

  local_sct.mutable_entry()->CopyFrom(*entry);
  delete entry;

  LogVerifier::VerifyResult result =
      verifier->VerifySignedCertificateTimestamp(local_sct);
  if (result != LogVerifier::VERIFY_OK)
    return result;
  sct->CopyFrom(local_sct);
  return LogVerifier::VERIFY_OK;
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
  // Uploads the bundle; if the server returns a signature token, writes
  // the token and returns true; else returns false.
  bool UploadBundle(const bstring &bundle, bool pre, bstring *token) {
    CTResponse response = Upload(bundle, pre);
    bool ret = false;
    switch (response.code) {
      case ct::ERROR:
        assert(response.data.size() == 1);
        std::cout << "Error: " << ErrorString(response.data[0]) << std::endl;
        break;
      case ct::SUBMITTED:
        std::cout << "Token is " << util::HexString(response.data, ' ')
                  << std::endl;
        if (token != NULL) {
          token->assign(response.data);
          ret = true;
        }
        break;
      default:
        std::cout << "Unknown response code." << std::endl;
    }
    return ret;
  }

  static std::string ErrorString(byte error) {
    switch(error) {
      case ct::BAD_VERSION:
        return "Bad version";
      case ct::BAD_COMMAND:
        return "Bad command";
      case ct::BAD_BUNDLE:
        return "Bad bundle";
      default:
        return "Unknown error code";
    }
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

  CTResponse Upload(const bstring &bundle, bool pre) {
    DLOG_BEGIN_CLIENT_MESSAGE;
    if (pre)
      WriteCommand(ct::UPLOAD_CA_BUNDLE);
    else
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
                                                 ca_dir_(NULL) {}

  SSLClient(const char *server, uint16_t port,
            const std::vector<bstring> &cache,
            const char *ca_dir) : CTClient(server, port),
                                   cache_(cache),
                                   ca_dir_(ca_dir) {}

  enum ConnectResult {
    PROOF_VERIFIED = 0,
    NO_VALID_PROOF = 2,
    // Found a valid proof that contradicts a previous, valid proof.
    INCONSISTENT_PROOF = 3,
  };

  std::vector<bstring> WriteCache() const {
    return cache_.WriteCache();
  }

  struct VerifyCallbackArgs {
    // The verifier for checking log proofs.
    LogVerifier *verifier;
    // The verification result.
    bool proof_verified;
    // The resulting checkpoint.
    SignedCertificateTimestamp sct;
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
    X509 *x509 = SSL_SESSION_get0_peer(sess);
    if (x509 == NULL) {
      // VerifyCallback should have caught that already.
      std::cout << "No server certificate received. Dropping connection." <<
          std::endl;
      return 0;
    }

    // Get the proof.
    size_t proof_length;
    unsigned char *proof =
        SSL_SESSION_get_tlsext_authz_server_audit_proof(sess, &proof_length);
    if (proof == NULL) {
      std::cout << "No log proof received. Dropping connection." << std::endl;
      return 0;
    }

    std::cout << "Found an audit proof in the TLS extension, verifying...";

    bstring proofstring(reinterpret_cast<byte*>(proof), proof_length);
    Cert *leaf = new Cert(x509);
    // TODO: also add the intermediates.
    CertChain chain;
    chain.AddCert(leaf);

    LogVerifier::VerifyResult result =
        VerifyLogSignature(proofstring, chain, verifier, &args->sct);

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

    CertChain chain;
    // ctx->untrusted is the chain of X509s, as passed in.
    // Let's hope OpenSSL keeps them in the order they were passed in.
    STACK_OF(X509) *sk = ctx->untrusted;
    assert(sk != NULL);
    int chain_size = sk_X509_num(sk);
    // Should contain at least the leaf.
    assert(chain_size >= 1);
    for (int i = 0; i < chain_size; ++i)
      chain.AddCert(new Cert(sk_X509_value(sk, i)));

    // First, see if the cert has an embedded proof.
    if (chain.LeafCert()->HasExtension(Cert::kEmbeddedProofExtensionOID)) {
      std::cout << "Embedded proof extension found in certificate, "
                << "verifying...";
      bstring proofstring =
          chain.LeafCert()->ExtensionData(Cert::kEmbeddedProofExtensionOID);

      // Only writes the checkpoint if verification succeeds.
      // Note: an optimized client could only verify the signature if it's
      // a checkpoint it hasn't seen before.
      LogVerifier::VerifyResult result = VerifyLogSignature(proofstring, chain,
                                                            verifier,
                                                            &args->sct);
      if (result == LogVerifier::VERIFY_OK) {
        std::cout << "OK" << std::endl;
        args->proof_verified = true;
      } else {
        std::cout << LogVerifier::VerifyResultString(result) << std::endl;
      }

      // Else look for the proof in a superfluous cert.
      // Let's assume the superfluous cert is always last in the chain.
    } else if (chain.Length() > 1 && chain.LastCert()->HasExtension(
        Cert::kProofExtensionOID)) {
      std::cout << "Proof extension found in certificate, verifying...";
      bstring proofstring = chain.LastCert()->ExtensionData(
          Cert::kProofExtensionOID);
      chain.RemoveCert();
      LogVerifier::VerifyResult result = VerifyLogSignature(proofstring, chain,
                                                            verifier,
                                                            &args->sct);
      if (result == LogVerifier::VERIFY_OK) {
        std::cout << "OK" << std::endl;
        args->proof_verified = true;
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
  ConnectResult SSLConnect(LogVerifier *verifier) {
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method());
    assert(ctx != NULL);
    // SSL_VERIFY_PEER makes the connection abort immediately
    // if verification fails.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // Set trusted CA certs.
    int ret;
    if (ca_dir_ != NULL) {
      ret = SSL_CTX_load_verify_locations(ctx, NULL, ca_dir_);
      assert(ret == 1);
    }
    VerifyCallbackArgs args;
    args.verifier = verifier;
    args.proof_verified = false;
    // The verify callback gets called before the audit proof callback.
    SSL_CTX_set_cert_verify_callback(ctx, &VerifyCallback, &args);
#ifdef TLSEXT_AUTHZDATAFORMAT_audit_proof
    SSL_CTX_set_tlsext_authz_server_audit_proof_cb(ctx, &AuditProofCallback);
    SSL_CTX_set_tlsext_authz_server_audit_proof_cb_arg(ctx, &args);
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

    ConnectResult result;
    // Cache the checkpoint.
    if (args.proof_verified) {
      switch(cache_.Insert(args.sct)) {
        case SCTCache::NEW:
          std::cout << "Cached new checkpoint." << std::endl;
          result = PROOF_VERIFIED;
          break;
        case SCTCache::CACHED:
          std::cout << "Checkpoint already in cache." << std::endl;
          result = PROOF_VERIFIED;
          break;
        case SCTCache::MISMATCH:
          std::cout << "ERROR: checkpoint mismatch!" << std::endl;
          result = INCONSISTENT_PROOF;
          break;
        default:
          assert(false);
      }
    } else {
      result = NO_VALID_PROOF;
    }

    // TODO: if the server closes the socket then the client cannot
    // connect again. Make sure we only allow SSLConnect() once.
    if (ssl) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
    }
    SSL_CTX_free(ctx);
    return result;
  }

 private:
  SCTCache cache_;
  const char *ca_dir_;
}; // class SSLCLient

static void UploadHelp() {
    std::cerr << "upload <file> <server> <port> [-server_key key_file] " <<
        "[-out proof_file] [-pre]" << std::endl;
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

  bool pre = false;

  argc -= 4;
  argv += 4;

  while (argc) {
    if (strcmp(argv[0], "-server_key") == 0) {
      if (key_file != NULL || argc == 1) {
        UploadHelp();
        exit(1);
      }
      key_file = argv[1];
      argc -= 2;
      argv += 2;
    } else if (strcmp(argv[0], "-out") == 0) {
      if (proof_file != NULL || argc == 1) {
        UploadHelp();
        exit(1);
      }
      proof_file = argv[1];
      argc -= 2;
      argv += 2;
    } else if (strcmp(argv[0], "-pre") == 0) {
      pre = true;
      --argc;
      ++argv;
    } else {
      UploadHelp();
      exit(1);
    }
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

  // Contents should be concatenated PEM entries.
  bstring contents;
  if (!util::ReadBinaryFile(file, &contents)) {
    perror(file);
    exit(1);
  }
  std::cout << file << " is " << contents.length() << " bytes." << std::endl;

  LogClient client(server_name, port);
  bstring proof;
  if(!client.UploadBundle(contents, pre, &proof)) {
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
    }
    // TODO: Process the |contents| bundle so that we can verify the proof.
    //      else {
    //       LogVerifier verifier(pkey);
    //       LogVerifier::VerifyResult result = VerifyLogSegmentProof(proof, contents,
    //                                                                &verifier, NULL);
    //       if (result == LogVerifier::VERIFY_OK)
    //         std::cout << "Proof verified." << std::endl;
    //       else
    //         std::cout << "ERROR: " << LogVerifier::VerifyResultString(result)
    //                   << std::endl;
    //     }
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
  AddExtension(x, Cert::kProofExtensionOID, proof, proof_len, 1);

  int i = i2d_X509_bio(out, x);
  assert(i != 0);

  BIO_free(out);
}

static const char kProofSectionPrefix[] = "1.2.3.1=DER:";

// A sample tool for CAs showing how to add the CT proof as an extension.
// We write the CT proof to the certificate config, so that we can
// sign using the standard openssl signing flow.
// Input:
// (1) an X509v3 configuration file
// (2) A binary proof file.
// Output:
// Append the following line to the end of the file.
// (This means the relevant section should be last in the configuration.)
// 1.2.3.1=DER:[raw encoding of proof]
static void WriteProofToConfig(int argc, const char **argv) {
  if (argc != 3) {
    std::cerr << argv[0] << " <config> <proof>\n";
    exit(1);
  }

  const char *conf_file = argv[1];
  const char *proof_file = argv[2];

  FILE *conf_fp = fopen(conf_file, "a");
    if (conf_fp == NULL) {
      perror(conf_file);
      exit(1);
    }

    FILE *proof_fp = fopen(proof_file, "rb");
    if (proof_fp == NULL) {
      perror(proof_file);
      exit(1);
    }

    fputs(kProofSectionPrefix, conf_fp);

    int proof_byte = fgetc(proof_fp);
    while (proof_byte != EOF) {
      fprintf(conf_fp, "%02X:", proof_byte);
      proof_byte = fgetc(proof_fp);
    };

    fclose(proof_fp);
    fprintf(conf_fp, "\n");
    fclose(conf_fp);
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
            << "[-cache cache_dir] [-ca_dir ca_dir]" << std::endl;
}

// Return values
//  0: a proof was successfully verified
//  2: no valid proof found
//  3: inconsistent proof
static int Connect(int argc, const char **argv) {
  if (argc < 3) {
    ConnectHelp();
    exit(1);
  }
  const char *server_name = argv[1];
  unsigned port = atoi(argv[2]);

  const char *key_file = NULL;
  const char *cache_dir = NULL;
  const char *ca_dir = NULL;

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
    } else if (strcmp(argv[0], "-ca_dir") == 0) {
      if (ca_dir != NULL) {
        ConnectHelp();
        exit(1);
      }
      ca_dir = argv[1];
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
    verifier = new LogVerifier(new LogSigVerifier(pkey),
                               new MerkleVerifier(new Sha256Hasher()));
  std::vector<bstring> cache;
  if (cache_dir != NULL) {
    std::cout << "Reading cache...";
    cache = ReadAllFiles(cache_dir);
    std::cout << "OK." << std::endl;
  }
  SSLClient client(server_name, port, cache, ca_dir);
  SSLClient::ConnectResult result = client.SSLConnect(verifier);
  if (cache_dir != NULL) {
    std::cout << "Writing cache...";
    cache = client.WriteCache();
    WriteAllFiles(cache, cache_dir);
    std::cout << "OK." << std::endl;
  }
  delete verifier;

  return result;
}

static void UsageHelp(const std::string &cmd) {
  std::cerr << cmd <<  " [-debug [-debug_out file]] <command> ..."
            << std::endl;
  std::cerr << "Known commands:" << std::endl;
  std::cerr << "connect - connect to an SSL server" << std::endl;
  std::cerr << "upload - upload a submission to a CT log server" << std::endl;
  std::cerr << "certificate - make a superfluous proof certificate" << std::endl;
  std::cerr << "authz - convert an audit proof to authz format" << std::endl;
  std::cerr << "configure_proof - write the proof in an X509v3 "
            << "configuration file" << std::endl;
}

static void UnknownCommand(const std::string &cmd,
                           const std::string &main_command) {
  std::cerr << "Unknown command: " << cmd << '\n';
  UsageHelp(main_command);
}

// Return value:
// 0: success
// 1: system error/invalid argument/etc
// 2: proof verification error (for Connect())
// 3: cache inconsistency error (for Connect())
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

  if (cmd == "connect")
    return Connect(argc, argv);

  if (cmd == "upload")
    Upload(argc, argv);
  else if (cmd == "certificate")
    MakeCert(argc, argv);
  else if (cmd == "authz")
    ProofToAuthz(argc, argv);
  else if (cmd == "configure_proof")
    WriteProofToConfig(argc, argv);
  else
    UnknownCommand(cmd, main_command);
}
