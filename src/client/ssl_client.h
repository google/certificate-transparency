#ifndef SSL_CLIENT_H
#define SSL_CLIENT_H

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "client/client.h"
#include "client/ssl_client.h"
#include "log/log_verifier.h"
#include "proto/ct.pb.h"

class LogVerifier;

class SSLClient {
 public:
  // Takes ownership of the verifier. This client can currently
  // only verify SCTs from a single log at a time.
  // TODO(ekasper): implement a proper multi-log auditor.
  SSLClient(const std::string &server, uint16_t port,
            const std::string &ca_dir, LogVerifier *verifier);

  ~SSLClient();

  enum HandshakeResult {
    OK = 0,
    HANDSHAKE_FAILED = 1,
    SERVER_UNAVAILABLE = 2,
  };

  HandshakeResult SSLConnect() {
    return SSLConnect(false);
  }

  // Same as above but won't proceed without an SCT.
  HandshakeResult SSLConnectStrict() {
    return SSLConnect(true);
  }

  bool Connected() const;

  void Disconnect();

  void GetSSLClientCTData(ct::SSLClientCTData *data) const;

  // Need a static wrapper for the callback.
  static LogVerifier::VerifyResult
  VerifySCT(const std::string &token, LogVerifier *verifier,
            ct::SSLClientCTData *data);

  // Custom verification callback for verifying the SCT token
  // in a superfluous certificate. Return values:
  // With TLS extension support:
  //  1 - cert verified (SCT might still be in TLS extension which is
  //      parsed in a later callback; we record whether it was verified
  //       in the callback args)
  // other values - cert verification errors.
  // Without TLS extension support, strict mode
  // 1 - cert and SCT verified
  // other values - everything else
  // Without TLS extension support, standard mode
  // 1 - cert verified (we record whether an SCT was also verified in the
  //     callback args)
  // other values - cert verification error
  static int VerifyCallback(X509_STORE_CTX *ctx, void *arg);

#ifdef TLSEXT_AUTHZDATAFORMAT_audit_proof
  // The callback for verifying the proof in a TLS extension. Return values:
  // Strict mode:
  // 1 - SCT already verified previously, or a valid SCT found in the extension
  // 0 - no valid token
  // Standard mode:
  // always 1
  static int SCTTokenCallback(SSL *s, void *arg);
#endif
 private:
  Client client_;
  SSL_CTX *ctx_;
  SSL *ssl_;
  struct VerifyCallbackArgs {
    VerifyCallbackArgs(LogVerifier *log_verifier)
        : verifier(log_verifier),
          token_verified(false),
          require_token(false),
          ct_data() {}

    // The verifier for checking log proofs.
    LogVerifier *verifier;
    // SCT verification result.
    bool token_verified;
    bool require_token;
    // The resulting (partial) entry - the client reconstructs
    // the signed part of the entry (i.e., type and leaf certificate)
    // and all valid SCTs.
    ct::SSLClientCTData ct_data;
  };

  VerifyCallbackArgs verify_args_;
  bool connected_;

  // Call before each handshake.
  void ResetVerifyCallbackArgs(bool strict);

  HandshakeResult SSLConnect(bool strict);
};
#endif
