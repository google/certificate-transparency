#ifndef TEST_SIGNER_H
#define TEST_SIGNER_H

#include <gtest/gtest.h>
#include <stdint.h>
#include <string>

#include "log/frontend_signer.h"
#include "log/log_signer.h"
#include "merkletree/tree_hasher.h"
#include "proto/ct.pb.h"

// Helper class for database tests that generates test data
// that roughly resembles real certificate data in shape and size.
class TestSigner {
 public:
  TestSigner();
  ~TestSigner();

  static LogSigner *DefaultSigner();

  static LogSigVerifier *DefaultVerifier();

  // For KAT tests: an SCT with a valid signature.
  // The default type is X509_ENTRY.
  static void SetDefaults(ct::LogEntry *entry);

  static void SetDefaults(ct::SignedCertificateTimestamp *sct);

  // For KAT tests: a logged cert with a valid hash and signature.
  // TODO(ekasper): add an intermediate for better coverage.
  static void SetDefaults(ct::LoggedCertificate *logged_cert);

  // For KAT tests: a tree head with a valid signature.
  // Uses SHA256 for the tree hash.
  static void SetDefaults(ct::SignedTreeHead *tree_head);

  // simulate a cert DER string - 512-1023 randomized (not random!) bytes.
  // The bytes are obtained by (a) copying chunks of 256 bytes from
  // offsets 0 - 255 of the default cert and (b) appending a counter value
  // (derived from current time) to further guarantee no collisions.
  // (Note that real DER certs always start with 0x30...)
  std::string UniqueFakeCertBytestring();

  // Sha256(counter).
  std::string UniqueHash();

  // Generates a randomized entry as follows:
  // type - chosen randomly between all options
  // leaf_certificate - 512-1023 randomized (not random!) bytes.
  // intermediates - 50%, none; 25%, 1; 25%, 2.
  void CreateUnique(ct::LogEntry *entry);

  // timestamp - current
  // signature - valid signature from the default signer
  // hash - valid sha256 hash of the leaf certificate
  // sequence number - cleared
  void CreateUnique(ct::LoggedCertificate *logged_cert);

  // Same as above but set the default signature to avoid overhead from signing.
  void CreateUniqueFakeSignature(ct::LoggedCertificate *logged_cert);

  // Generates a randomized entry as follows:
  // timestamp - current
  // tree size - [0, RAND_MAX]
  // root hash - random unique hash
  // signature - valid on the above
  void CreateUnique(ct::SignedTreeHead *sth);

  // Helper methods for unit tests. Compare protobufs with a set of
  // EXPECT_EQ macros.

  static void TestEqualDigitallySigned(const ct::DigitallySigned &ds0,
                                       const ct::DigitallySigned &ds1);

  static void TestEqualX509Entries(const ct::X509ChainEntry &entry0,
                                   const ct::X509ChainEntry &entry1);

  static void TestEqualPreEntries(const ct::PrecertChainEntry &entry0,
                                  const ct::PrecertChainEntry &entry1);

  static void TestEqualEntries(const ct::LogEntry &entry0,
                               const ct::LogEntry &entry1);

  static void TestEqualSCTs(const ct::SignedCertificateTimestamp &sct0,
                            const ct::SignedCertificateTimestamp &sct1);

  static void TestEqualLoggedCerts(const ct::LoggedCertificate &c1,
                                   const ct::LoggedCertificate &c2);

  static void TestEqualTreeHeads(const ct::SignedTreeHead &sth1,
                                 const ct::SignedTreeHead &sth2);

 private:

  // Fill everything apart from the signature.
  void FillData(ct::LoggedCertificate *logged_cert);
  LogSigner *default_signer_;
  // ct::SignedCertificateTimestamp default_sct_;
  // ct::SignedTreeHead default_sth_;
  uint64_t counter_;
  // Binary blob.
  std::string default_cert_;
  TreeHasher tree_hasher_;
};
#endif
