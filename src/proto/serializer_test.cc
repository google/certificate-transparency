#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <string>

#include "ct.pb.h"
#include "serializer.h"
#include "types.h"
#include "util.h"

namespace {

using ct::DigitallySigned;
using ct::LogEntry;
using ct::LogEntryType;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;
using ct::Version;
using std::string;

// A slightly shorter notation for constructing binary blobs from test vectors.
string S(const char *hexstring) {
  return string(hexstring);
}

string B(const char *hexstring) {
  return util::BinaryString(hexstring);
}

// The reverse.
string H(const string &byte_string) {
  return util::HexString(byte_string);
}

// TODO(ekasper): switch to real data here, too.
class SerializerTest : public ::testing::Test {
 protected:
  SerializerTest() : sct_(), sth_() {
    entry_.set_type(ct::X509_ENTRY);
    entry_.mutable_x509_entry()->set_leaf_certificate("certificate");
    sct_.set_version(ct::V1);
    sct_.set_timestamp(1234);
    sct_.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
    sct_.mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
    sct_.mutable_signature()->set_signature("signature");
    sth_.set_version(ct::V1);
    sth_.set_timestamp(2345);
    sth_.set_tree_size(6);
    sth_.set_root_hash("imustbeexactlythirtytwobyteslong");
    sth_.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
    sth_.mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
    sth_.mutable_signature()->set_signature("tree_signature");
  }

  const LogEntry &DefaultEntry() const { return entry_; }

  uint64_t DefaultSCTTimestamp() const { return sct_.timestamp(); }

  LogEntryType DefaultEntryType() const { return entry_.type(); }

  string DefaultCertificate() const {
    return entry_.x509_entry().leaf_certificate();
  }

  string DefaultExtensions() const { return string(); }

  const SignedCertificateTimestamp &DefaultSCT() const { return sct_; }

  uint64_t DefaultSTHTimestamp() const { return sth_.timestamp(); }

  uint64_t DefaultTreeSize() const { return sth_.tree_size(); }

  string DefaultRootHash() const { return sth_.root_hash(); }

  const SignedTreeHead &DefaultSTH() const { return sth_; }

  const DigitallySigned &DefaultSCTSignature() const {
    return sct_.signature();
  }

  const DigitallySigned &DefaultSTHSignature() const {
    return sth_.signature();
  }

  static void CompareDS(const DigitallySigned &ds, const DigitallySigned &ds2) {
    EXPECT_EQ(ds.hash_algorithm(), ds2.hash_algorithm());
    EXPECT_EQ(ds.sig_algorithm(), ds2.sig_algorithm());
    EXPECT_EQ(H(ds.signature()), H(ds2.signature()));
  }

  static void CompareSCT(const SignedCertificateTimestamp &sct,
                         const SignedCertificateTimestamp &sct2) {
    EXPECT_EQ(sct.version(), sct2.version());
    EXPECT_EQ(sct.timestamp(), sct2.timestamp());
    CompareDS(sct.signature(), sct2.signature());
  }

 private:
  SignedCertificateTimestamp sct_;
  LogEntry entry_;
  SignedTreeHead sth_;
};

const char kDefaultSCTSignatureHexString[] =
    // hash algo, sig algo, 2 bytes
    "0403"
    // signature length, 2 bytes
    "0009"
    // signature, 9 bytes
    "7369676e6174757265";

const char kDefaultSCTHexString[] =
    // version, 1 byte
    "00"
    // timestamp, 8 bytes
    "00000000000004d2"
    // extensions length, 2 bytes
    "0000"
    // extensions, 0 bytes
    // hash algo, sig algo, 2 bytes
    "0403"
    // signature length, 2 bytes
    "0009"
    // signature, 9 bytes
    "7369676e6174757265";

const char kDefaultSCTSignedHexString[] =
    // version, 1 byte
    "00"
    // signature type, 1 byte
    "00"
    // timestamp, 8 bytes
    "00000000000004d2"
    // entry type, 2 bytes
    "0000"
    // leaf certificate length, 3 bytes
    "00000b"
    // leaf certificate, 11 bytes
    "6365727469666963617465"
    // extensions length, 2 bytes
    "0000";
    // extensions, 0 bytes

const char kDefaultSTHSignedHexString[] =
    // version, 1 byte
    "00"
    // signature type, 1 byte
    "01"
    // timestamp, 8 bytes
    "0000000000000929"
    // tree size, 8 bytes
    "0000000000000006"
    // root hash, 32 bytes
    "696d757374626565786163746c7974686972747974776f62797465736c6f6e67";

TEST_F(SerializerTest, SerializeDigitallySignedKatTest) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeDigitallySigned(DefaultSCTSignature(),
                                                 &result));
  EXPECT_EQ(S(kDefaultSCTSignatureHexString), H(result));
}

TEST_F(SerializerTest, SerializeSCTKatTest) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCT(DefaultSCT(), &result));
  EXPECT_EQ(S(kDefaultSCTHexString), H(result));
}

TEST_F(SerializerTest, SerializeSCTSignatureInputKatTest) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeV1SCTSignatureInput(
                DefaultSCTTimestamp(), DefaultEntryType(),
                DefaultCertificate(), DefaultExtensions(), &result));
  EXPECT_EQ(S(kDefaultSCTSignedHexString), H(result));

  result.clear();
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTSignatureInput(
                DefaultSCT(), DefaultEntry(), &result));
  EXPECT_EQ(S(kDefaultSCTSignedHexString), H(result));
}

TEST_F(SerializerTest, DeserializeSCTKatTest) {
  string token = B(kDefaultSCTHexString);
  SignedCertificateTimestamp sct;
  EXPECT_EQ(Deserializer::OK, Deserializer::DeserializeSCT(token, &sct));
  CompareSCT(DefaultSCT(), sct);
}

TEST_F(SerializerTest, DeserializeDigitallySignedKatTest) {
  string serialized_sig = B(kDefaultSCTSignatureHexString);
  DigitallySigned signature;
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeDigitallySigned(serialized_sig,
                                                     &signature));
  CompareDS(DefaultSCTSignature(), signature);
}

// Test that the serialized string changes when we change some values.
TEST_F(SerializerTest, SerializeSCTSignatureInputChangeEntryType) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeV1SCTSignatureInput(
                DefaultSCTTimestamp(), ct::PRECERT_ENTRY,
                DefaultCertificate(), DefaultExtensions(), &result));

  string default_result = S(kDefaultSCTSignedHexString);
  string new_result = H(result);
  EXPECT_EQ(default_result.size(), new_result.size());
  EXPECT_NE(default_result, new_result);

  result.clear();
  LogEntry entry;
  entry.CopyFrom(DefaultEntry());
  entry.set_type(ct::PRECERT_ENTRY);
  entry.mutable_precert_entry()->set_tbs_certificate(
      entry.x509_entry().leaf_certificate());
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTSignatureInput(
                DefaultSCT(), entry, &result));

  new_result = H(result);
  EXPECT_EQ(default_result.size(), new_result.size());
  EXPECT_NE(default_result, new_result);
}

TEST_F(SerializerTest, SerializeDeserializeSCTChangeHashAlgorithm) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA224);

  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCT(sct, &result));

  string default_result = S(kDefaultSCTHexString);
  string new_result = H(result);
  EXPECT_EQ(default_result.size(), new_result.size());
  EXPECT_NE(default_result, new_result);

  SignedCertificateTimestamp read_sct;
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeSCT(result, &read_sct));
  CompareSCT(read_sct, sct);
}

TEST_F(SerializerTest, SerializeDeserializeSCTChangeSignature) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.mutable_signature()->set_signature("bazinga");

  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCT(sct, &result));
  EXPECT_NE(S(kDefaultSCTHexString), H(result));

  SignedCertificateTimestamp read_sct;
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeSCT(result, &read_sct));
  CompareSCT(read_sct, sct);
}

TEST_F(SerializerTest, SerializeSCTSignatureInputEmptyCertificate) {
  string result;
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeV1SCTSignatureInput(
                DefaultSCTTimestamp(), DefaultEntryType(),
                string(), DefaultExtensions(), &result));

  LogEntry entry;
  entry.CopyFrom(DefaultEntry());
  entry.mutable_x509_entry()->clear_leaf_certificate();
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeSCTSignatureInput(DefaultSCT(), entry,
                                                   &result));
}

TEST_F(SerializerTest, DeserializeSCTBadHashType) {
  string token = B(kDefaultSCTHexString);
  // Overwrite with a non-existent hash algorithm type.
  token[11] = 0xff;

  SignedCertificateTimestamp sct;
  EXPECT_EQ(Deserializer::INVALID_HASH_ALGORITHM,
            Deserializer::DeserializeSCT(token, &sct));
}

TEST_F(SerializerTest, DeserializeSCTBadSignatureType) {
  string token = B(kDefaultSCTHexString);
  // Overwrite with a non-existent signature algorithm type.
  token[12] = 0xff;

  SignedCertificateTimestamp sct;
  EXPECT_EQ(Deserializer::INVALID_SIGNATURE_ALGORITHM,
            Deserializer::DeserializeSCT(token, &sct));
}

TEST_F(SerializerTest, DeserializeSCTTooShort) {
  string token = B(kDefaultSCTHexString);

  for (size_t i = 0; i < token.size(); ++i) {
    SignedCertificateTimestamp sct;
    EXPECT_EQ(Deserializer::INPUT_TOO_SHORT,
              Deserializer::DeserializeSCT(token.substr(0, i), &sct));
  }
}

TEST_F(SerializerTest, DeserializeSCTTooLong) {
  string token = B(kDefaultSCTHexString);
  token.push_back(0x42);

  SignedCertificateTimestamp sct;

  // We can still read from the beginning of a longer string...
  Deserializer deserializer(token);
  EXPECT_EQ(Deserializer::OK, deserializer.ReadSCT(&sct));
  EXPECT_FALSE(deserializer.ReachedEnd());
  CompareSCT(DefaultSCT(), sct);

  // ... but we can't deserialize.
  EXPECT_EQ(Deserializer::INPUT_TOO_LONG,
            Deserializer::DeserializeSCT(token, &sct));
}

TEST_F(SerializerTest, SerializeSTHSignatureInputKatTest) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSTHSignatureInput(DefaultSTH(), &result));
  EXPECT_EQ(S(kDefaultSTHSignedHexString), H(result));

  result.clear();
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeV1STHSignatureInput(
                DefaultSTHTimestamp(), DefaultTreeSize(),
                DefaultRootHash(), &result));
  EXPECT_EQ(S(kDefaultSTHSignedHexString), H(result));
}

TEST_F(SerializerTest, SerializeSTHSignatureInputBadHash) {
  SignedTreeHead sth;
  sth.CopyFrom(DefaultSTH());
  sth.set_root_hash("thisisnotthirtytwobyteslong");
  string result;
  EXPECT_EQ(Serializer::INVALID_HASH_LENGTH,
            Serializer::SerializeSTHSignatureInput(sth, &result));
}

TEST_F(SerializerTest, SerializeSCTWithExtensionsTest) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.set_extension("hello");
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCT(sct, &result));
  EXPECT_NE(S(kDefaultSCTHexString), H(result));
}

TEST_F(SerializerTest, SerializeSCTSignatureInputWithExtensionsTest) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeV1SCTSignatureInput(
                DefaultSCTTimestamp(), DefaultEntryType(),
                DefaultCertificate(), "hello", &result));
  EXPECT_NE(S(kDefaultSCTSignedHexString), H(result));

  result.clear();
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.set_extension("hello");
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTSignatureInput(
                sct, DefaultEntry(), &result));
  EXPECT_NE(S(kDefaultSCTSignedHexString), H(result));
}

TEST_F(SerializerTest, SerializeDeserializeSCTAddExtensions) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.set_extension("hello");

  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCT(sct, &result));

  SignedCertificateTimestamp read_sct;
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeSCT(result, &read_sct));
  CompareSCT(sct, read_sct);
}

TEST_F(SerializerTest, SerializeSCTUnsupportedVersion) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.set_version(ct::UNKNOWN_VERSION);

  string result;
  EXPECT_EQ(Serializer::UNSUPPORTED_VERSION,
            Serializer::SerializeSCT(sct, &result));
}

TEST_F(SerializerTest, SerializeSCTSignatureInputUnsupportedVersion) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.set_version(ct::UNKNOWN_VERSION);

  string result;
  EXPECT_EQ(Serializer::UNSUPPORTED_VERSION,
            Serializer::SerializeSCTSignatureInput(sct, DefaultEntry(),
                                                   &result));
}

TEST_F(SerializerTest, SerializeSTHSignatureInputUnsupportedVersion) {
  SignedTreeHead sth;
  sth.CopyFrom(DefaultSTH());
  sth.set_version(ct::UNKNOWN_VERSION);

  string result;
  EXPECT_EQ(Serializer::UNSUPPORTED_VERSION,
            Serializer::SerializeSTHSignatureInput(sth, &result));
}

TEST_F(SerializerTest, DeserializeSCTUnsupportedVersion) {
  string token = B(kDefaultSCTHexString);
  // Overwrite with a non-existent version.
  token[0] = 0xff;

  SignedCertificateTimestamp sct;
  EXPECT_EQ(Deserializer::UNSUPPORTED_VERSION,
            Deserializer::DeserializeSCT(token, &sct));
}

}  // namespace

int main(int argc, char**argv) {
  // Change the defaults. Can be overridden on command line.
  // Log to stderr instead of log files.
  FLAGS_logtostderr = true;
  // Only log fatal messages by default.
  FLAGS_minloglevel = 3;
  ::testing::InitGoogleTest(&argc, argv);
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
