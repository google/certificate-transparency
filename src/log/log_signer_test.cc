#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <string>

#include "ct.pb.h"
#include "log_signer.h"
#include "serializer.h"
#include "types.h"
#include "util.h"

namespace {

using ct::CertificateEntry;
using ct::SignedCertificateTimestamp;
using ct::DigitallySigned;

// A slightly shorter notation for constructing binary blobs from test vectors.
std::string S(const char *hexstring, size_t byte_length) {
  return std::string(hexstring, 2 * byte_length);
}

bstring B(const char *hexstring, size_t byte_length) {
  return util::BinaryString(S(hexstring, byte_length));
}

// The reverse.
std::string H(const bstring &byte_string) {
  return util::HexString(byte_string);
}

const char *ecp256_private_key = {
  "-----BEGIN EC PRIVATE KEY-----\n"
  "MHcCAQEEIG8QAquNnarN6Ik2cMIZtPBugh9wNRe0e309MCmDfBGuoAoGCCqGSM49\n"
  "AwEHoUQDQgAES0AfBkjr7b8b19p5Gk8plSAN16wWXZyhYsH6FMCEUK60t7pem/ck\n"
  "oPX8hupuaiJzJS0ZQ0SEoJGlFxkUFwft5g==\n"
  "-----END EC PRIVATE KEY-----\n"
};

const char *ecp256_public_key = {
  "-----BEGIN PUBLIC KEY-----\n"
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES0AfBkjr7b8b19p5Gk8plSAN16wW\n"
  "XZyhYsH6FMCEUK60t7pem/ckoPX8hupuaiJzJS0ZQ0SEoJGlFxkUFwft5g==\n"
  "-----END PUBLIC KEY-----\n"
};

EVP_PKEY* PrivateKeyFromPem(const std::string &pemkey) {
  BIO *bio = BIO_new_mem_buf(const_cast<char*>(pemkey.data()), pemkey.size());
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  assert(pkey != NULL);
  BIO_free(bio);
  return pkey;
}

EVP_PKEY* PublicKeyFromPem(const std::string &pemkey) {
  BIO *bio = BIO_new_mem_buf(const_cast<char*>(pemkey.data()), pemkey.size());
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  assert(pkey != NULL);
  BIO_free(bio);
  return pkey;
}

// A valid signature on the default SCT, using the private key above.
const char kDefaultSCTSignature[] =
    "3046022100ee89fb556fd72264098e8c80da9141c2aa2a788587bcc73d235ff7fd42dd5a11"
    "022100a3df4dd9c6cc6374ec1a7ba06d3a3c791e542287819fe1a15ca134d9cbb8bb74";

const size_t kDefaultSCTSignatureLength = 72;

class LogSignerTest : public ::testing::Test {
 protected:
  LogSignerTest() : signer_(NULL),
                    verifier_(NULL),
                    sct_() {
    sct_.set_timestamp(1234);
    sct_.mutable_entry()->set_type(CertificateEntry::X509_ENTRY);
    sct_.mutable_entry()->set_leaf_certificate("certificate");
    sct_.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
    sct_.mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
    sct_.mutable_signature()->set_signature(B(kDefaultSCTSignature,
                                              kDefaultSCTSignatureLength));
  }

  const SignedCertificateTimestamp &DefaultSCT() const { return sct_; }

  uint64_t DefaultTimestamp() const { return sct_.timestamp(); }

  const bstring &DefaultCert() const {
    return sct_.entry().leaf_certificate();
  }

  LogSigner::CertificateEntryType DefaultType() const {
    return static_cast<LogSigner::CertificateEntryType>(sct_.entry().type());
  }

  const DigitallySigned &DefaultSignature() const { return sct_.signature(); }

  bstring DefaultSerializedSignature() const {
    bstring serialized_sig;
    Serializer::SerializeDigitallySigned(DefaultSignature(), &serialized_sig);
    return serialized_sig;
  }

  void SetUp() {
    EVP_PKEY *pkey = PrivateKeyFromPem(ecp256_private_key);
    EVP_PKEY *pubkey = PublicKeyFromPem(ecp256_public_key);
    signer_ = new LogSigner(pkey);
    verifier_ = new LogSigVerifier(pubkey);
    ASSERT_TRUE(signer_ != NULL);
    ASSERT_TRUE(verifier_ != NULL);
  }

  ~LogSignerTest() {
    delete signer_;
    delete verifier_;
  }

  LogSigner *signer_;
  LogSigVerifier *verifier_;
  SignedCertificateTimestamp sct_;
};

TEST_F(LogSignerTest, VerifyKatTest) {
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(DefaultSCT()));
  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(DefaultTimestamp(), DefaultType(),
                                          DefaultCert(),
                                          DefaultSerializedSignature()));
}

TEST_F(LogSignerTest, SignAndVerifySCT) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.clear_signature();
  ASSERT_FALSE(sct.has_signature());

  EXPECT_EQ(LogSigner::OK, signer_->SignCertificateTimestamp(&sct));
  EXPECT_TRUE(sct.has_signature());
  EXPECT_EQ(DefaultSignature().hash_algorithm(),
            sct.signature().hash_algorithm());
  EXPECT_EQ(DefaultSignature().sig_algorithm(),
            sct.signature().sig_algorithm());
  // We should get a fresh signature.
  EXPECT_NE(H(DefaultSignature().signature()), H(sct.signature().signature()));
  // But it should still be valid.
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  // The second version.
  bstring serialized_sig;
  EXPECT_EQ(LogSigner::OK,
            signer_->SignCertificateTimestamp(DefaultTimestamp(), DefaultType(),
                                              DefaultCert(), &serialized_sig));
  EXPECT_NE(H(DefaultSerializedSignature()), H(serialized_sig));
  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(DefaultTimestamp(), DefaultType(),
                                          DefaultCert(), serialized_sig));
}

TEST_F(LogSignerTest, SignAndVerifyApiCrossCheck) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.clear_signature();

  EXPECT_EQ(LogSigner::OK, signer_->SignCertificateTimestamp(&sct));

  // Serialize and verify.
  bstring serialized_sig;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeDigitallySigned(sct.signature(),
                                                 &serialized_sig));
  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(DefaultTimestamp(), DefaultType(),
                                          DefaultCert(), serialized_sig));


  // The second version.
  serialized_sig.clear();
  EXPECT_EQ(LogSigner::OK,
            signer_->SignCertificateTimestamp(DefaultTimestamp(), DefaultType(),
                                              DefaultCert(), &serialized_sig));

  // Deserialize and verify.
  sct.clear_signature();
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeDigitallySigned(serialized_sig,
                                                     sct.mutable_signature()));
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));
}

TEST_F(LogSignerTest, SignInvalidType) {
  bstring serialized_sig;
  EXPECT_EQ(LogSigner::INVALID_ENTRY_TYPE, signer_->SignCertificateTimestamp(
      DefaultTimestamp(),
      static_cast<LogSigner::CertificateEntryType>(-1),
      DefaultCert(),
      &serialized_sig));
}

TEST_F(LogSignerTest, SignEmptyCert) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.clear_signature();
  sct.mutable_entry()->clear_leaf_certificate();

  EXPECT_EQ(LogSigner::EMPTY_CERTIFICATE,
            signer_->SignCertificateTimestamp(&sct));

  bstring serialized_sig;
  bstring empty_cert;
  EXPECT_EQ(LogSigner::EMPTY_CERTIFICATE,
            signer_->SignCertificateTimestamp(DefaultTimestamp(), DefaultType(),
                                              empty_cert,
                                              &serialized_sig));
}

TEST_F(LogSignerTest, VerifyChangeTimestamp) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  sct.set_timestamp(4321);
  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(sct));

  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(DefaultTimestamp(), DefaultType(),
                                          DefaultCert(),
                                          DefaultSerializedSignature()));

  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(4321, DefaultType(), DefaultCert(),
                                          DefaultSerializedSignature()));
}

TEST_F(LogSignerTest, VerifyChangeType) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  sct.mutable_entry()->set_type(CertificateEntry::PRECERT_ENTRY);
  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(sct));

  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(DefaultTimestamp(), DefaultType(),
                                          DefaultCert(),
                                          DefaultSerializedSignature()));

  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(DefaultTimestamp(),
                                          LogSigner::PRECERT_ENTRY,
                                          DefaultCert(),
                                          DefaultSerializedSignature()));
}

TEST_F(LogSignerTest, VerifyChangeCert) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  sct.mutable_entry()->set_leaf_certificate("bazinga");
  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(sct));

  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(DefaultTimestamp(), DefaultType(),
                                          DefaultCert(),
                                          DefaultSerializedSignature()));

  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(DefaultTimestamp(), DefaultType(),
                                          "bazinga",
                                          DefaultSerializedSignature()));
}

TEST_F(LogSignerTest, VerifyBadHashAlgorithm) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  sct.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA224);
  EXPECT_EQ(LogSigVerifier::HASH_ALGORITHM_MISMATCH,
            verifier_->VerifySCTSignature(sct));
}

TEST_F(LogSignerTest, VerifyBadSignatureAlgorithm) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  sct.mutable_signature()->set_sig_algorithm(DigitallySigned::DSA);
  EXPECT_EQ(LogSigVerifier::SIGNATURE_ALGORITHM_MISMATCH,
            verifier_->VerifySCTSignature(sct));
}

TEST_F(LogSignerTest, VerifyBadSignature) {
  SignedCertificateTimestamp sct;
  // Too short.
  sct.CopyFrom(DefaultSCT());
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  bstring bad_signature = DefaultSignature().signature();
  bad_signature.erase(bad_signature.end() - 1);
  sct.mutable_signature()->set_signature(bad_signature);
  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(sct));

  // Too long.
  // Apparently, OpenSSL Verify parses *up to* a given number of bytes,
  // rather than exactly the given number of bytes, and hence appending
  // garbage in the end still results in a valid signature?
  // sct.CopyFrom(DefaultSCT());
  // EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  // bad_signature = DefaultSignature().signature();
  // bad_signature.push_back(0x42);

  // sct.mutable_signature()->set_signature(bad_signature);
  // EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
  // verifier_->VerifySCTSignature(sct));

  // Flip the lsb of each byte one by one.
  for (size_t i = 0; i < DefaultSignature().signature().size(); ++i) {
    sct.CopyFrom(DefaultSCT());
    EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

    bad_signature = DefaultSignature().signature();
    bad_signature[i] ^= 0x01;
    sct.mutable_signature()->set_signature(bad_signature);
    EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
              verifier_->VerifySCTSignature(sct));
  }
}

TEST_F(LogSignerTest, VerifyBadSerializedSignature) {
  bstring serialized_sig = DefaultSerializedSignature();
  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(DefaultTimestamp(), DefaultType(),
                                          DefaultCert(), serialized_sig));
  // Too short.
  bstring bad_signature = serialized_sig.substr(0, serialized_sig.size() - 1);
  EXPECT_EQ(LogSigVerifier::SIGNATURE_TOO_SHORT,
            verifier_->VerifySCTSignature(DefaultTimestamp(), DefaultType(),
                                          DefaultCert(), bad_signature));
  // Too long.
  bad_signature = serialized_sig;
  bad_signature.push_back(0x42);
  EXPECT_EQ(LogSigVerifier::SIGNATURE_TOO_LONG,
            verifier_->VerifySCTSignature(DefaultTimestamp(), DefaultType(),
                                          DefaultCert(), bad_signature));

  // Flip the lsb of each byte one by one.
  for (size_t i = 0; i < serialized_sig.size(); ++i) {
    bad_signature = serialized_sig;
    bad_signature[i] ^= 0x01;
    // Error codes vary, depending on which byte was flipped.
    EXPECT_NE(LogSigVerifier::OK,
              verifier_->VerifySCTSignature(DefaultTimestamp(), DefaultType(),
                                            DefaultCert(), bad_signature));
  }
}

}  // namespace

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
