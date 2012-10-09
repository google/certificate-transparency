#include <glog/logging.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "cert.h"
#include "cert_submission_handler.h"
#include "client.h"
#include "log_verifier.h"
#include "ssl_client.h"

using ct::SignedCertificateTimestamp;
using ct::CertificateEntry;
using std::string;

SSLClient::SSLClient(const string &server, uint16_t port,
                     const string &ca_dir, LogVerifier *verifier)
    : client_(server, port),
      ctx_(NULL),
      verify_args_(verifier),
      connected_(false) {
  ctx_ = SSL_CTX_new(TLSv1_client_method());
  CHECK_NOTNULL(ctx_);

  // SSL_VERIFY_PEER makes the connection abort immediately
  // if verification fails.
  SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, NULL);
  // Set trusted CA certs.
  if (!ca_dir.empty()) {
    CHECK_EQ(1, SSL_CTX_load_verify_locations(ctx_, NULL, ca_dir.c_str()))
        << "Unable to load trusted CA certificates.";
  } else {
    LOG(WARNING) << "No trusted CA certificates given.";
  }

  // The verify callback gets called before the audit proof callback.
  SSL_CTX_set_cert_verify_callback(ctx_, &VerifyCallback, &verify_args_);
#ifdef TLSEXT_AUTHZDATAFORMAT_audit_proof
    SSL_CTX_set_tlsext_authz_server_audit_proof_cb(ctx_, &SCTTokenCallback);
    SSL_CTX_set_tlsext_authz_server_audit_proof_cb_arg(ctx_, &verify_args_);
#endif
}

SSLClient::~SSLClient() {
  Disconnect();
  if (ctx_ != NULL)
    SSL_CTX_free(ctx_);
  delete verify_args_.verifier;
}

bool SSLClient::Connected() const {
  return connected_;
}

void SSLClient::Disconnect() {
  if (ssl_ != NULL) {
    SSL_shutdown(ssl_);
    SSL_free(ssl_);
    ssl_ = NULL;
    LOG(INFO) << "SSL session finished";
  }
  client_.Disconnect();
  connected_ = false;
}

bool SSLClient::GetToken(SignedCertificateTimestamp *sct) const {
  CHECK(Connected());
  if (verify_args_.token_verified) {
    sct->CopyFrom(verify_args_.sct);
    return true;
  }
  return false;
}

// static
LogVerifier::VerifyResult
SSLClient::VerifySCT(const string &token, const CertChain &chain,
                     LogVerifier *verifier, SignedCertificateTimestamp *sct) {
  CertificateEntry entry;
  if (CertSubmissionHandler::X509ChainToEntry(chain, &entry) !=
      SubmissionHandler::OK)
    return LogVerifier::INVALID_FORMAT;

  SignedCertificateTimestamp local_sct;
  if (Deserializer::DeserializeSCTToken(token, &local_sct) != Deserializer::OK)
    return LogVerifier::INVALID_FORMAT;

  local_sct.mutable_entry()->CopyFrom(entry);

  LogVerifier::VerifyResult result =
      verifier->VerifySignedCertificateTimestamp(local_sct);
  if (result != LogVerifier::VERIFY_OK)
    return result;
  sct->CopyFrom(local_sct);
  return LogVerifier::VERIFY_OK;
}

// static
int SSLClient::VerifyCallback(X509_STORE_CTX *ctx, void *arg) {
  VerifyCallbackArgs *args = reinterpret_cast<VerifyCallbackArgs*>(arg);
  CHECK_NOTNULL(args);
  LogVerifier *verifier = args->verifier;
  CHECK_NOTNULL(verifier);

  int vfy = X509_verify_cert(ctx);
  if (vfy != 1) {
    LOG(ERROR) << "Certificate verification failed.";
    return vfy;
  }

  // If verify passed then surely we must have a cert.
  CHECK_NOTNULL(ctx->cert);

  CertChain chain;
  // ctx->untrusted is the chain of X509s, as passed in.
  // Let's hope OpenSSL keeps them in the order they were passed in.
  STACK_OF(X509) *sk = ctx->untrusted;
  CHECK_NOTNULL(sk);
  int chain_size = sk_X509_num(sk);
  // Should contain at least the leaf.
  CHECK_GE(chain_size, 1);
  for (int i = 0; i < chain_size; ++i)
    chain.AddCert(new Cert(sk_X509_value(sk, i)));

  string token;
  // First, see if the cert has an embedded proof.
  if (chain.LeafCert()->HasExtension(Cert::kEmbeddedProofExtensionOID)) {
    LOG(INFO) << "Embedded proof extension found in certificate, "
              << "verifying...";
    token = chain.LeafCert()->ExtensionData(Cert::kEmbeddedProofExtensionOID);
    // Else look for the proof in a superfluous cert.
    // Let's assume the superfluous cert is always last in the chain.
  } else if (chain.Length() > 1 && chain.LastCert()->HasExtension(
      Cert::kProofExtensionOID)) {
    LOG(INFO) << "Proof extension found in certificate, verifying...";
    token = chain.LastCert()->ExtensionData(
        Cert::kProofExtensionOID);
    chain.RemoveCert();
  }

  if (!token.empty()) {
    // Only writes the checkpoint if verification succeeds.
    // Note: an optimized client could only verify the signature if it's
    // a certificate it hasn't seen before.
    LogVerifier::VerifyResult result = VerifySCT(token, chain,
                                                 verifier, &args->sct);

    if (result == LogVerifier::VERIFY_OK) {
      LOG(INFO) << "Token verified";
      args->token_verified = true;
    } else {
      LOG(ERROR) << "Verification failed: "
                 << LogVerifier::VerifyResultString(result);
    }
  }

#ifndef TLSEXT_AUTHZDATAFORMAT_audit_proof
  // If we don't support the TLS extension, we fail here. Else we wait to see
  // if the extension callback finds a valid proof.
  if (!args->token_verified && args->require_token) {
    LOG(ERROR) << "No valid SCT found";
    return 0;
  }
#endif
  return 1;
}

#ifdef TLSEXT_AUTHZDATAFORMAT_audit_proof
// static
int SSLClient::SCTTokenCallback(SSL *s, void *arg) {
  VerifyCallbackArgs *args = reinterpret_cast<VerifyCallbackArgs*>(arg);
  CHECK_NOTNULL(args);
  // If we already received the proof in a superfluous cert, do nothing.
  if (args->token_verified)
    return 1;

  LogVerifier *verifier = args->verifier;
  CHECK_NOTNULL(verifier);

  SSL_SESSION *sess = SSL_get_session(s);
  // Get the leaf certificate.
  X509 *x509 = SSL_SESSION_get0_peer(sess);
  CHECK_NOTNULL(x509);

  // Get the token.
  size_t proof_length;
  unsigned char *proof =
      SSL_SESSION_get_tlsext_authz_server_audit_proof(sess, &proof_length);
  if (proof == NULL) {
    LOG(WARNING) << "No SCT received.";
    return args->require_token ? 0 : 1;
  }

  LOG(INFO) << "Found an SCT token in the TLS extension, verifying...";

  string token(reinterpret_cast<char*>(proof), proof_length);
  Cert *leaf = new Cert(x509);
  CertChain chain;
  chain.AddCert(leaf);

  LogVerifier::VerifyResult result =
      VerifySCT(token, chain, verifier, &args->sct);

  if (result == LogVerifier::VERIFY_OK) {
    args->token_verified = true;
    LOG(INFO) << "Token verified";
    return 1;
  } else {
    LOG(ERROR) << "Verification failed: "
               << LogVerifier::VerifyResultString(result);
    return args->require_token ? 0 : 1;
  }
}
#endif

void SSLClient::ResetVerifyCallbackArgs(bool strict) {
  verify_args_.token_verified = false;
  verify_args_.require_token = strict;
  verify_args_.sct.CopyFrom(SignedCertificateTimestamp::default_instance());
}

SSLClient::HandshakeResult SSLClient::SSLConnect(bool strict) {
  if (!client_.Connect())
    return SERVER_UNAVAILABLE;

  ssl_ = SSL_new(ctx_);
  CHECK_NOTNULL(ssl_);
  BIO *bio = BIO_new_socket(client_.fd(), BIO_NOCLOSE);
  CHECK_NOTNULL(bio);
  // Takes ownership of bio.
  SSL_set_bio(ssl_, bio, bio);

  ResetVerifyCallbackArgs(strict);
  int ret = SSL_connect(ssl_);
  HandshakeResult result;
  if (ret == 1) {
    LOG(INFO) << "Handshake successful. SSL session started";
    connected_ = true;
    DCHECK(!verify_args_.require_token || verify_args_.token_verified);
    result = OK;
  } else {
    // TODO(ekasper): look into OpenSSL error stack to determine
    // the error reason. Could be unrelated to SCT verification.
    LOG(ERROR) << "SSL handshake failed";
    result = HANDSHAKE_FAILED;
    Disconnect();
  }
  return result;
}
