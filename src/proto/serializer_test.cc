#include <gtest/gtest.h>
#include <string>

#include "ct.pb.h"
#include "serializer.h"
#include "types.h"
#include "util.h"

namespace {

using ct::CertificateEntry;
using ct::DigitallySigned;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;
using std::string;

// A slightly shorter notation for constructing binary blobs from test vectors.
string S(const char *hexstring, size_t byte_length) {
  return string(hexstring, 2 * byte_length);
}

string B(const char *hexstring, size_t byte_length) {
  return util::BinaryString(S(hexstring, byte_length));
}

// The reverse.
string H(const string &byte_string) {
  return util::HexString(byte_string);
}

class SerializerTest : public ::testing::Test {
 protected:
  SerializerTest() : sct_(), sth_() {
    sct_.set_timestamp(1234);
    sct_.mutable_entry()->set_type(CertificateEntry::X509_ENTRY);
    sct_.mutable_entry()->set_leaf_certificate("certificate");
    sct_.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
    sct_.mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
    sct_.mutable_signature()->set_signature("signature");
    sth_.set_timestamp(2345);
    sth_.set_tree_size(6);
    sth_.set_root_hash("imustbeexactlythirtytwobyteslong");
    sth_.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
    sth_.mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
    sth_.mutable_signature()->set_signature("tree_signature");
  }

  const SignedCertificateTimestamp &DefaultSCT() const { return sct_; }

  const SignedTreeHead &DefaultSTH() const { return sth_; }

  const DigitallySigned &DefaultDS() const { return sct_.signature(); }

  static void CompareDS(const DigitallySigned &ds, const DigitallySigned &ds2) {
    EXPECT_EQ(ds.hash_algorithm(), ds2.hash_algorithm());
    EXPECT_EQ(ds.sig_algorithm(), ds2.sig_algorithm());
    EXPECT_EQ(H(ds.signature()), H(ds2.signature()));
  }

  static void CompareSCTToken(const SignedCertificateTimestamp &sct,
                              const SignedCertificateTimestamp &sct2) {
    EXPECT_EQ(sct.timestamp(), sct2.timestamp());
    CompareDS(sct.signature(), sct2.signature());
  }

 private:
  SignedCertificateTimestamp sct_;
  SignedTreeHead sth_;
};

const char kDefaultDSHexString[] =
    // hash algo, sig algo, 2 bytes
    "0403"
    // signature length, 2 bytes
    "0009"
    // signature, 9 bytes
    "7369676e6174757265";

const size_t kDefaultDSLength = 13;

const char kDefaultSCTTokenHexString[] =
    // timestamp, 8 bytes
    "00000000000004d2"
    // hash algo, sig algo, 2 bytes
    "0403"
    // signature length, 2 bytes
    "0009"
    // signature, 9 bytes
    "7369676e6174757265";

const size_t kDefaultSCTTokenLength = 21;

const char kDefaultSCTSignedHexString[] =
    // timestamp, 8 bytes
    "00000000000004d2"
    // type, 1 byte
    "00"
    // leaf certificate length, 3 bytes
    "00000b"
    // leaf certificate, 11 bytes
    "6365727469666963617465";

const size_t kDefaultSCTSignedLength = 23;

const char kDefaultSTHSignedHexString[] =
    // timestamp, 8 bytes
    "0000000000000929"
    // tree size, 8 bytes
    "0000000000000006"
    // root hash, 32 bytes
    "696d757374626565786163746c7974686972747974776f62797465736c6f6e67";

const size_t kSTHSignedLength = 48;

TEST_F(SerializerTest, SerializeDigitallySignedKatTest) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeDigitallySigned(DefaultDS(), &result));
  EXPECT_EQ(S(kDefaultDSHexString, kDefaultDSLength), H(result));
}

TEST_F(SerializerTest, SerializeSCTTokenKatTest) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTToken(DefaultSCT(), &result));
  EXPECT_EQ(S(kDefaultSCTTokenHexString, kDefaultSCTTokenLength), H(result));
}

TEST_F(SerializerTest, SerializeSCTForSigningKatTest) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTForSigning(DefaultSCT(), &result));
  EXPECT_EQ(S(kDefaultSCTSignedHexString, kDefaultSCTSignedLength), H(result));
}

TEST_F(SerializerTest, DeserializeSCTTokenKatTest) {
  string token = B(kDefaultSCTTokenHexString, kDefaultSCTTokenLength);
  SignedCertificateTimestamp sct;
  EXPECT_EQ(Deserializer::OK, Deserializer::DeserializeSCTToken(token, &sct));
  CompareSCTToken(DefaultSCT(), sct);
}

TEST_F(SerializerTest, DeserializeDigitallySignedKatTest) {
  string serialized_sig = B(kDefaultDSHexString, kDefaultDSLength);
  DigitallySigned signature;
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeDigitallySigned(serialized_sig,
                                                     &signature));
  CompareDS(DefaultDS(), signature);
}

// Test that the serialized string changes when we change some values.
TEST_F(SerializerTest, SerializeSCTForSigningChangeType) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.mutable_entry()->set_type(CertificateEntry::PRECERT_ENTRY);
  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCTForSigning(sct, &result));

  string default_result =
      S(kDefaultSCTSignedHexString, kDefaultSCTSignedLength);
  string new_result = H(result);
  EXPECT_EQ(default_result.size(), new_result.size());
  EXPECT_NE(default_result, new_result);
}

TEST_F(SerializerTest, SerializeDeserializeSCTTokenChangeHashAlgorithm) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA224);

  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCTToken(sct, &result));

  string default_result =
      S(kDefaultSCTTokenHexString, kDefaultSCTTokenLength);
  string new_result = H(result);
  EXPECT_EQ(default_result.size(), new_result.size());
  EXPECT_NE(default_result, new_result);

  SignedCertificateTimestamp read_sct;
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeSCTToken(result, &read_sct));
  CompareSCTToken(read_sct, sct);
}

TEST_F(SerializerTest, SerializeDeserializeSCTTokenChangeSignature) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.mutable_signature()->set_signature("bazinga");

  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCTToken(sct, &result));
  EXPECT_NE(S(kDefaultSCTTokenHexString, kDefaultSCTTokenLength), H(result));

  SignedCertificateTimestamp read_sct;
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeSCTToken(result, &read_sct));
  CompareSCTToken(read_sct, sct);
}

TEST_F(SerializerTest, SerializeSCTForSigningEmptyCertificate) {
  SignedCertificateTimestamp sct;
  sct.CopyFrom(DefaultSCT());
  sct.mutable_entry()->set_leaf_certificate("");
  string result;
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeSCTForSigning(sct, &result));
}

TEST_F(SerializerTest, DeserializeSCTTokenBadHashType) {
  string token = B(kDefaultSCTTokenHexString, kDefaultSCTTokenLength);
  // Overwrite with a non-existent hash algorithm type.
  token[8] = 0xff;

  SignedCertificateTimestamp sct;
  EXPECT_EQ(Deserializer::INVALID_HASH_ALGORITHM,
            Deserializer::DeserializeSCTToken(token, &sct));
}

TEST_F(SerializerTest, DeserializeSCTTokenBadSignatureType) {
  string token = B(kDefaultSCTTokenHexString, kDefaultSCTTokenLength);
  // Overwrite with a non-existent signature algorithm type.
  token[9] = 0xff;

  SignedCertificateTimestamp sct;
  EXPECT_EQ(Deserializer::INVALID_SIGNATURE_ALGORITHM,
            Deserializer::DeserializeSCTToken(token, &sct));
}

TEST_F(SerializerTest, DeserializeSCTTokenTooShort) {
  string token = B(kDefaultSCTTokenHexString, kDefaultSCTTokenLength);

  for (size_t i = 0; i < token.size(); ++i) {
    SignedCertificateTimestamp sct;
    EXPECT_EQ(Deserializer::INPUT_TOO_SHORT,
              Deserializer::DeserializeSCTToken(token.substr(0, i), &sct));
  }
}

TEST_F(SerializerTest, DeserializeSCTTokenTooLong) {
  string token = B(kDefaultSCTTokenHexString, kDefaultSCTTokenLength);
  token.push_back(0x42);

  SignedCertificateTimestamp sct;

  // We can still read from the beginning of a longer string...
  Deserializer deserializer(token);
  EXPECT_EQ(Deserializer::OK, deserializer.ReadSCTToken(&sct));
  EXPECT_FALSE(deserializer.ReachedEnd());
  CompareSCTToken(DefaultSCT(), sct);

  // ... but we can't deserialize.
  EXPECT_EQ(Deserializer::INPUT_TOO_LONG,
            Deserializer::DeserializeSCTToken(token, &sct));
}

TEST_F(SerializerTest, SerializeSTHForSigningKatTest) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSTHForSigning(DefaultSTH(), &result));
  EXPECT_EQ(S(kDefaultSTHSignedHexString, kSTHSignedLength), H(result));
}

TEST_F(SerializerTest, SerializeSTHForSigningBadHash) {
  SignedTreeHead sth;
  sth.CopyFrom(DefaultSTH());
  sth.set_root_hash("thisisnotthirtytwobyteslong");
  string result;
  EXPECT_EQ(Serializer::INVALID_HASH_LENGTH,
            Serializer::SerializeSTHForSigning(sth, &result));
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
