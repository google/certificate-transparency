#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <stdint.h>
#include <string>

#include "ct.pb.h"
#include "log_signer.h"
#include "serializer.h"
#include "test_signer.h"
#include "util.h"

namespace {

using ct::CertificateEntry;
using ct::CertificateEntryType;
using ct::SignedCertificateTimestamp;
using ct::DigitallySigned;
using ct::SignedTreeHead;
using std::string;

// A slightly shorter notation for constructing hex strings from binary blobs.
string H(const string &byte_string) {
  return util::HexString(byte_string);
}

class LogSignerTest : public ::testing::Test {
 protected:
  LogSignerTest() : signer_(NULL),
                    verifier_(NULL) {}

  void SetUp() {
    signer_ = TestSigner::DefaultSigner();
    verifier_ = TestSigner::DefaultVerifier();
  }

  ~LogSignerTest() {
    delete signer_;
    delete verifier_;
  }

  // For the protobuf-agnostic version. The enum values are required to match,
  // so we convert by name.
  static ct::CertificateEntryType SignedType(
      CertificateEntry::Type type) {
    switch (type) {
      case CertificateEntry::X509_ENTRY:
        return ct::X509_ENTRY;
      case CertificateEntry::PRECERT_ENTRY:
        return ct::PRECERT_ENTRY;
      default:
        DLOG(FATAL) << "Unknown entry type " << type;
    }
  }

  static string SerializedSignature(const DigitallySigned &signature) {
    string serialized_sig;
    CHECK_EQ(Serializer::OK,
             Serializer::SerializeDigitallySigned(signature,
                                                  &serialized_sig));
    return serialized_sig;
  }

  LogSigner *signer_;
  LogSigVerifier *verifier_;
  TestSigner test_signer_;
};

TEST_F(LogSignerTest, VerifySCTKatTest) {
  SignedCertificateTimestamp default_sct;
  TestSigner::SetDefaults(&default_sct);

  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(default_sct));

  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                default_sct.entry().leaf_certificate(),
                SerializedSignature(default_sct.signature())));
}

TEST_F(LogSignerTest, VerifySTHKatTest) {
  SignedTreeHead default_sth;
  TestSigner::SetDefaults(&default_sth);

  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySTHSignature(default_sth));

  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySTHSignature(
                default_sth.timestamp(), default_sth.tree_size(),
                default_sth.root_hash(),
                SerializedSignature(default_sth.signature())));
}

TEST_F(LogSignerTest, SignAndVerifySCT) {
  SignedCertificateTimestamp default_sct, sct;
  TestSigner::SetDefaults(&default_sct);
  sct.CopyFrom(default_sct);
  sct.clear_signature();
  ASSERT_FALSE(sct.has_signature());

  EXPECT_EQ(LogSigner::OK, signer_->SignCertificateTimestamp(&sct));
  EXPECT_TRUE(sct.has_signature());
  EXPECT_EQ(default_sct.signature().hash_algorithm(),
            sct.signature().hash_algorithm());
  EXPECT_EQ(default_sct.signature().sig_algorithm(),
            sct.signature().sig_algorithm());
  // We should get a fresh signature.
  EXPECT_NE(H(default_sct.signature().signature()),
            H(sct.signature().signature()));
  // But it should still be valid.
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  // The second version.
  string serialized_sig;
  EXPECT_EQ(LogSigner::OK,
            signer_->SignCertificateTimestamp(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                default_sct.entry().leaf_certificate(), &serialized_sig));

  string default_serialized_sig = SerializedSignature(default_sct.signature());
  EXPECT_NE(H(default_serialized_sig), H(serialized_sig));
  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                default_sct.entry().leaf_certificate(),
                default_serialized_sig));
}

TEST_F(LogSignerTest, SignAndVerifySTH) {
  SignedTreeHead default_sth, sth;
  TestSigner::SetDefaults(&default_sth);
  sth.CopyFrom(default_sth);
  sth.clear_signature();
  ASSERT_FALSE(sth.has_signature());

  EXPECT_EQ(LogSigner::OK, signer_->SignTreeHead(&sth));
  EXPECT_TRUE(sth.has_signature());
  EXPECT_EQ(default_sth.signature().hash_algorithm(),
            sth.signature().hash_algorithm());
  EXPECT_EQ(default_sth.signature().sig_algorithm(),
            sth.signature().sig_algorithm());
  // We should get a fresh signature.
  EXPECT_NE(H(default_sth.signature().signature()),
            H(sth.signature().signature()));
  // But it should still be valid.
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySTHSignature(sth));

  // The second version.
  string serialized_sig;
  EXPECT_EQ(LogSigner::OK,
            signer_->SignTreeHead(
                default_sth.timestamp(), default_sth.tree_size(),
                default_sth.root_hash(), &serialized_sig));

  string default_serialized_sig = SerializedSignature(default_sth.signature());
  EXPECT_NE(H(default_serialized_sig), H(serialized_sig));
  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySTHSignature(
                default_sth.timestamp(), default_sth.tree_size(),
                default_sth.root_hash(), default_serialized_sig));
}

TEST_F(LogSignerTest, SignAndVerifySCTApiCrossCheck) {
  SignedCertificateTimestamp default_sct, sct;
  TestSigner::SetDefaults(&default_sct);
  sct.CopyFrom(default_sct);
  sct.clear_signature();

  EXPECT_EQ(LogSigner::OK, signer_->SignCertificateTimestamp(&sct));

  // Serialize and verify.
  string serialized_sig;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeDigitallySigned(sct.signature(),
                                                 &serialized_sig));
  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                default_sct.entry().leaf_certificate(), serialized_sig));

  // The second version.
  serialized_sig.clear();
  EXPECT_EQ(LogSigner::OK,
            signer_->SignCertificateTimestamp(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                default_sct.entry().leaf_certificate(), &serialized_sig));

  // Deserialize and verify.
  sct.clear_signature();
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeDigitallySigned(serialized_sig,
                                                     sct.mutable_signature()));
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));
}

TEST_F(LogSignerTest, SignAndVerifySTHApiCrossCheck) {
  SignedTreeHead default_sth, sth;
  TestSigner::SetDefaults(&default_sth);
  sth.CopyFrom(default_sth);
  sth.clear_signature();

  EXPECT_EQ(LogSigner::OK, signer_->SignTreeHead(&sth));

  // Serialize and verify.
  string serialized_sig;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeDigitallySigned(sth.signature(),
                                                 &serialized_sig));
  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySTHSignature(
                default_sth.timestamp(), default_sth.tree_size(),
                default_sth.root_hash(), serialized_sig));

  // The second version.
  serialized_sig.clear();
  EXPECT_EQ(LogSigner::OK,
            signer_->SignTreeHead(
                default_sth.timestamp(), default_sth.tree_size(),
                default_sth.root_hash(), &serialized_sig));

  // Deserialize and verify.
  sth.clear_signature();
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeDigitallySigned(serialized_sig,
                                                     sth.mutable_signature()));
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySTHSignature(sth));
}

TEST_F(LogSignerTest, SignInvalidType) {
  SignedCertificateTimestamp default_sct, sct;
  TestSigner::SetDefaults(&default_sct);
  string serialized_sig;
  EXPECT_EQ(LogSigner::INVALID_ENTRY_TYPE, signer_->SignCertificateTimestamp(
      default_sct.timestamp(),
      static_cast<ct::CertificateEntryType>(-1),
      default_sct.entry().leaf_certificate(),
      &serialized_sig));
}

TEST_F(LogSignerTest, SignEmptyCert) {
  SignedCertificateTimestamp default_sct, sct;
  TestSigner::SetDefaults(&default_sct);
  sct.CopyFrom(default_sct);
  sct.clear_signature();
  sct.mutable_entry()->clear_leaf_certificate();

  EXPECT_EQ(LogSigner::EMPTY_CERTIFICATE,
            signer_->SignCertificateTimestamp(&sct));

  string serialized_sig;
  string empty_cert;
  EXPECT_EQ(LogSigner::EMPTY_CERTIFICATE,
            signer_->SignCertificateTimestamp(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                empty_cert, &serialized_sig));
}

TEST_F(LogSignerTest, SignBadRootHash) {
  SignedTreeHead default_sth, sth;
  TestSigner::SetDefaults(&default_sth);
  sth.CopyFrom(default_sth);
  sth.clear_signature();
  sth.set_root_hash("bad");

  EXPECT_EQ(LogSigner::INVALID_HASH_LENGTH, signer_->SignTreeHead(&sth));

  string serialized_sig;
  EXPECT_EQ(LogSigner::INVALID_HASH_LENGTH,
            signer_->SignTreeHead(default_sth.timestamp(),
                                  default_sth.tree_size(), "bad",
                                  &serialized_sig));
}

TEST_F(LogSignerTest, VerifyChangeSCTTimestamp) {
  SignedCertificateTimestamp default_sct, sct;
  TestSigner::SetDefaults(&default_sct);
  sct.CopyFrom(default_sct);
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  uint64_t new_timestamp = default_sct.timestamp() + 1000;

  sct.set_timestamp(new_timestamp);
  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(sct));

  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                default_sct.entry().leaf_certificate(),
                SerializedSignature(default_sct.signature())));

  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(
                new_timestamp, SignedType(default_sct.entry().type()),
                default_sct.entry().leaf_certificate(),
                SerializedSignature(default_sct.signature())));
}

TEST_F(LogSignerTest, VerifyChangeSTHTimestamp) {
  SignedTreeHead default_sth, sth;
  TestSigner::SetDefaults(&default_sth);
  sth.CopyFrom(default_sth);
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySTHSignature(sth));

  uint64_t new_timestamp = default_sth.timestamp() + 1000;
  sth.set_timestamp(new_timestamp);
  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySTHSignature(sth));

  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySTHSignature(
                default_sth.timestamp(), default_sth.tree_size(),
                default_sth.root_hash(),
                SerializedSignature(default_sth.signature())));

  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySTHSignature(
                new_timestamp, default_sth.tree_size(),
                default_sth.root_hash(),
                SerializedSignature(default_sth.signature())));
}

TEST_F(LogSignerTest, VerifyChangeType) {
  SignedCertificateTimestamp default_sct, sct;
  TestSigner::SetDefaults(&default_sct);
  sct.CopyFrom(default_sct);
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  CHECK_NE(CertificateEntry::PRECERT_ENTRY, sct.entry().type());
  sct.mutable_entry()->set_type(CertificateEntry::PRECERT_ENTRY);
  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(sct));

  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                default_sct.entry().leaf_certificate(),
                SerializedSignature(default_sct.signature())));


  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(
                default_sct.timestamp(),
                SignedType(CertificateEntry::PRECERT_ENTRY),
                default_sct.entry().leaf_certificate(),
                SerializedSignature(default_sct.signature())));
}

TEST_F(LogSignerTest, VerifyChangeCert) {
  SignedCertificateTimestamp default_sct, sct, sct2;
  TestSigner::SetDefaults(&default_sct);
  sct.CopyFrom(default_sct);
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  string new_cert = test_signer_.UniqueFakeCertBytestring();
  sct.mutable_entry()->set_leaf_certificate(new_cert);

  // Check that we can successfully sign and verify the new sct.
  sct2.CopyFrom(sct);
  EXPECT_EQ(LogSigner::OK, signer_->SignCertificateTimestamp(&sct2));
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct2));

  // We should not be able to verify the new cert with the old signature.
  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(sct));

  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                default_sct.entry().leaf_certificate(),
                SerializedSignature(default_sct.signature())));
  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                new_cert, SerializedSignature(default_sct.signature())));
}

TEST_F(LogSignerTest, VerifyChangeTreeSize) {
  SignedTreeHead default_sth, sth;
  TestSigner::SetDefaults(&default_sth);
  sth.CopyFrom(default_sth);
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySTHSignature(sth));

  uint64_t new_tree_size = default_sth.tree_size() + 1;
  sth.set_tree_size(new_tree_size);
  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySTHSignature(sth));

  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySTHSignature(
                default_sth.timestamp(), default_sth.tree_size(),
                default_sth.root_hash(),
                SerializedSignature(default_sth.signature())));

  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySTHSignature(
                default_sth.timestamp(), new_tree_size,
                default_sth.root_hash(),
                SerializedSignature(default_sth.signature())));
}

TEST_F(LogSignerTest, VerifySCTBadHashAlgorithm) {
  SignedCertificateTimestamp default_sct, sct;
  TestSigner::SetDefaults(&default_sct);
  sct.CopyFrom(default_sct);
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  CHECK_NE(DigitallySigned::SHA224, sct.signature().hash_algorithm());
  sct.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA224);
  EXPECT_EQ(LogSigVerifier::HASH_ALGORITHM_MISMATCH,
            verifier_->VerifySCTSignature(sct));
}

TEST_F(LogSignerTest, VerifySTHBadHashAlgorithm) {
  SignedTreeHead default_sth, sth;
  TestSigner::SetDefaults(&default_sth);
  sth.CopyFrom(default_sth);
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySTHSignature(sth));

  CHECK_NE(DigitallySigned::SHA224, sth.signature().hash_algorithm());
  sth.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA224);
  EXPECT_EQ(LogSigVerifier::HASH_ALGORITHM_MISMATCH,
            verifier_->VerifySTHSignature(sth));
}

TEST_F(LogSignerTest, VerifySCTBadSignatureAlgorithm) {
  SignedCertificateTimestamp default_sct, sct;
  TestSigner::SetDefaults(&default_sct);
  sct.CopyFrom(default_sct);
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  CHECK_NE(DigitallySigned::DSA, sct.signature().sig_algorithm());
  sct.mutable_signature()->set_sig_algorithm(DigitallySigned::DSA);
  EXPECT_EQ(LogSigVerifier::SIGNATURE_ALGORITHM_MISMATCH,
            verifier_->VerifySCTSignature(sct));
}

TEST_F(LogSignerTest, VerifySTHBadSignatureAlgorithm) {
  SignedTreeHead default_sth, sth;
  TestSigner::SetDefaults(&default_sth);
  sth.CopyFrom(default_sth);
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySTHSignature(sth));

  CHECK_NE(DigitallySigned::DSA, sth.signature().sig_algorithm());
  sth.mutable_signature()->set_sig_algorithm(DigitallySigned::DSA);
  EXPECT_EQ(LogSigVerifier::SIGNATURE_ALGORITHM_MISMATCH,
            verifier_->VerifySTHSignature(sth));
}

TEST_F(LogSignerTest, VerifyBadSCTSignature) {
  SignedCertificateTimestamp default_sct, sct;
  TestSigner::SetDefaults(&default_sct);
  // Too short.
  sct.CopyFrom(default_sct);
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  string bad_signature = default_sct.signature().signature();
  bad_signature.erase(bad_signature.end() - 1);
  sct.mutable_signature()->set_signature(bad_signature);
  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySCTSignature(sct));

  // Too long.
  // OpenSSL ECDSA Verify parses *up to* a given number of bytes,
  // rather than exactly the given number of bytes, and hence appending
  // garbage in the end still results in a valid signature.
  // sct.CopyFrom(default_sct);
  // EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

  // bad_signature = default_sct.signature().signature();
  // bad_signature.push_back(0x42);

  // sct.mutable_signature()->set_signature(bad_signature);
  // EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
  // verifier_->VerifySCTSignature(sct));

  // Flip the lsb of each byte one by one.
  for (size_t i = 0; i < default_sct.signature().signature().size(); ++i) {
    sct.CopyFrom(default_sct);
    EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySCTSignature(sct));

    bad_signature = default_sct.signature().signature();
    bad_signature[i] ^= 0x01;
    sct.mutable_signature()->set_signature(bad_signature);
    EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
              verifier_->VerifySCTSignature(sct));
  }
}

TEST_F(LogSignerTest, VerifyBadSTHSignature) {
  SignedTreeHead default_sth, sth;
  TestSigner::SetDefaults(&default_sth);
  // Too short.
  sth.CopyFrom(default_sth);
  EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySTHSignature(sth));

  string bad_signature = default_sth.signature().signature();
  bad_signature.erase(bad_signature.end() - 1);
  sth.mutable_signature()->set_signature(bad_signature);
  EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
            verifier_->VerifySTHSignature(sth));

  // Too long.
  // OpenSSL ECDSA Verify parses *up to* a given number of bytes,
  // rather than exactly the given number of bytes, and hence appending
  // garbage in the end still results in a valid signature.
  // sth.CopyFrom(default_sth);
  // EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySTHSignature(sth));

  // bad_signature = default_sth.signature().signature();
  // bad_signature.push_back(0x42);

  // sth.mutable_signature()->set_signature(bad_signature);
  // EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
  // verifier_->VerifySTHSignature(sth));

  // Flip the lsb of each byte one by one.
  for (size_t i = 0; i < default_sth.signature().signature().size(); ++i) {
    sth.CopyFrom(default_sth);
    EXPECT_EQ(LogSigVerifier::OK, verifier_->VerifySTHSignature(sth));

    bad_signature = default_sth.signature().signature();
    bad_signature[i] ^= 0x01;
    sth.mutable_signature()->set_signature(bad_signature);
    EXPECT_EQ(LogSigVerifier::INVALID_SIGNATURE,
              verifier_->VerifySTHSignature(sth));
  }
}

TEST_F(LogSignerTest, VerifyBadSerializedSCTSignature) {
  SignedCertificateTimestamp default_sct, sct;
  TestSigner::SetDefaults(&default_sct);
  string serialized_sig = SerializedSignature(default_sct.signature());
  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySCTSignature(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                default_sct.entry().leaf_certificate(), serialized_sig));
  // Too short.
  string bad_signature = serialized_sig.substr(0, serialized_sig.size() - 1);
  EXPECT_EQ(LogSigVerifier::SIGNATURE_TOO_SHORT,
            verifier_->VerifySCTSignature(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                default_sct.entry().leaf_certificate(), bad_signature));
  // Too long.
  bad_signature = serialized_sig;
  bad_signature.push_back(0x42);
  EXPECT_EQ(LogSigVerifier::SIGNATURE_TOO_LONG,
            verifier_->VerifySCTSignature(
                default_sct.timestamp(), SignedType(default_sct.entry().type()),
                default_sct.entry().leaf_certificate(), bad_signature));

  // Flip the lsb of each byte one by one.
  for (size_t i = 0; i < serialized_sig.size(); ++i) {
    bad_signature = serialized_sig;
    bad_signature[i] ^= 0x01;
    // Error codes vary, depending on which byte was flipped.
    EXPECT_NE(LogSigVerifier::OK,
              verifier_->VerifySCTSignature(
                  default_sct.timestamp(),
                  SignedType(default_sct.entry().type()),
                  default_sct.entry().leaf_certificate(), bad_signature));
  }
}

TEST_F(LogSignerTest, VerifyBadSerializedSTHSignature) {
  SignedTreeHead default_sth, sth;
  TestSigner::SetDefaults(&default_sth);
  string serialized_sig = SerializedSignature(default_sth.signature());
  EXPECT_EQ(LogSigVerifier::OK,
            verifier_->VerifySTHSignature(
                default_sth.timestamp(), default_sth.tree_size(),
                default_sth.root_hash(), serialized_sig));
  // Too short.
  string bad_signature = serialized_sig.substr(0, serialized_sig.size() - 1);
  EXPECT_EQ(LogSigVerifier::SIGNATURE_TOO_SHORT,
            verifier_->VerifySTHSignature(
                default_sth.timestamp(), default_sth.tree_size(),
                default_sth.root_hash(), bad_signature));
  // Too long.
  bad_signature = serialized_sig;
  bad_signature.push_back(0x42);
  EXPECT_EQ(LogSigVerifier::SIGNATURE_TOO_LONG,
            verifier_->VerifySTHSignature(
                default_sth.timestamp(), default_sth.tree_size(),
                default_sth.root_hash(), bad_signature));

  // Flip the lsb of each byte one by one.
  for (size_t i = 0; i < serialized_sig.size(); ++i) {
    bad_signature = serialized_sig;
    bad_signature[i] ^= 0x01;
    // Error codes vary, depending on which byte was flipped.
    EXPECT_NE(LogSigVerifier::OK,
              verifier_->VerifySTHSignature(
                  default_sth.timestamp(), default_sth.tree_size(),
                  default_sth.root_hash(), bad_signature));
  }
}

}  // namespace

int main(int argc, char **argv) {
  // Change the defaults. Can be overridden on command line.
  // Log to stderr instead of log files.
  FLAGS_logtostderr = true;
  // Only log fatal messages by default.
  FLAGS_minloglevel = 3;
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
