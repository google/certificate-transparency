#include <gtest/gtest.h>
#include <string>

#include "../include/types.h"
#include "../util/util.h"
#include "ct.pb.h"
#include "serializer.h"

namespace {

class SerializerTest : public ::testing::Test {
 protected:
  SerializerTest() : sch_() {
    sch_.set_timestamp(1234);
    sch_.mutable_entry()->set_type(CertificateEntry::X509_ENTRY);
    sch_.mutable_entry()->set_leaf_certificate("certificate");
    sch_.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
    sch_.mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
    sch_.mutable_signature()->set_signature("signature");
  }

  const SignedCertificateHash &DefaultSCH() const { return sch_; }

  static void CompareSCHToken(const SignedCertificateHash &sch,
                              const SignedCertificateHash &sch2) {
    EXPECT_EQ(sch.timestamp(), sch2.timestamp());
    EXPECT_EQ(sch.signature().hash_algorithm(),
              sch2.signature().hash_algorithm());
    EXPECT_EQ(sch.signature().sig_algorithm(),
              sch2.signature().sig_algorithm());;
    EXPECT_EQ(sch.signature().signature(), sch2.signature().signature());
  }

 private:
  SignedCertificateHash sch_;
};

const char kDefaultSCHTokenHexString[] =
    // timestamp, 8 bytes
    "00000000000004d2"
    // hash algo, sig algo, 2 bytes
    "0403"
    // signature length, 2 bytes
    "0009"
    // signature, 9 bytes
    "7369676e6174757265";

const size_t kDefaultSCHTokenLength = 21;

const char kDefaultSCHSignedHexString[] =
    // timestamp, 8 bytes
    "00000000000004d2"
    // type, 1 byte
    "00"
    // leaf certificate length, 3 bytes
    "00000b"
    // leaf certificate, 11 bytes
    "6365727469666963617465";

const size_t kDefaultSCHSignedLength = 23;

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

TEST_F(SerializerTest, SerializeSCHTokenKatTest) {
  bstring result;
  EXPECT_TRUE(Serializer::SerializeSCHToken(DefaultSCH(), &result));
  EXPECT_EQ(S(kDefaultSCHTokenHexString, kDefaultSCHTokenLength), H(result));
}

TEST_F(SerializerTest, SerializeSCHForSigningKatTest) {
  bstring result;
  EXPECT_TRUE(Serializer::SerializeForSigning(DefaultSCH(), &result));
  EXPECT_EQ(S(kDefaultSCHSignedHexString, kDefaultSCHSignedLength), H(result));
}

TEST_F(SerializerTest, DeserializeSCHTokenKatTest) {
  bstring token = B(kDefaultSCHTokenHexString, kDefaultSCHTokenLength);
  SignedCertificateHash sch;
  EXPECT_TRUE(Deserializer::DeserializeSCHToken(token, &sch));
  CompareSCHToken(DefaultSCH(), sch);
}

// Test that the serialized string changes when we change some values.
TEST_F(SerializerTest, SerializeSCHForSigningChangeType) {
  SignedCertificateHash sch;
  sch.CopyFrom(DefaultSCH());
  sch.mutable_entry()->set_type(CertificateEntry::PRECERT_ENTRY);
  bstring result;
  EXPECT_TRUE(Serializer::SerializeForSigning(sch, &result));

  std::string default_result =
      S(kDefaultSCHSignedHexString, kDefaultSCHSignedLength);
  std::string new_result = H(result);
  EXPECT_EQ(default_result.size(), new_result.size());
  EXPECT_NE(default_result, new_result);
}

TEST_F(SerializerTest, SerializeDeserializeSCHTokenChangeHashAlgorithm) {
  SignedCertificateHash sch;
  sch.CopyFrom(DefaultSCH());
  sch.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA224);

  bstring result;
  EXPECT_TRUE(Serializer::SerializeSCHToken(sch, &result));

  std::string default_result =
      S(kDefaultSCHTokenHexString, kDefaultSCHTokenLength);
  std::string new_result = H(result);
  EXPECT_EQ(default_result.size(), new_result.size());
  EXPECT_NE(default_result, new_result);

  SignedCertificateHash read_sch;
  EXPECT_TRUE(Deserializer::DeserializeSCHToken(result, &read_sch));
  CompareSCHToken(read_sch, sch);
}

TEST_F(SerializerTest, SerializeDeserializeSCHTokenChangeSignature) {
  SignedCertificateHash sch;
  sch.CopyFrom(DefaultSCH());
  sch.mutable_signature()->set_signature("bazinga");

  bstring result;
  EXPECT_TRUE(Serializer::SerializeSCHToken(sch, &result));
  EXPECT_NE(S(kDefaultSCHTokenHexString, kDefaultSCHTokenLength), H(result));

  SignedCertificateHash read_sch;
  EXPECT_TRUE(Deserializer::DeserializeSCHToken(result, &read_sch));
  CompareSCHToken(read_sch, sch);
}

TEST_F(SerializerTest, DeserializeSCHTokenBadHashType) {
  bstring token = B(kDefaultSCHTokenHexString, kDefaultSCHTokenLength);
  // Overwrite with a non-existent hash algorithm type.
  token[8] = 0xff;

  SignedCertificateHash sch;
  EXPECT_FALSE(Deserializer::DeserializeSCHToken(token, &sch));
}

TEST_F(SerializerTest, DeserializeSCHTokenBadSignatureType) {
  bstring token = B(kDefaultSCHTokenHexString, kDefaultSCHTokenLength);
  // Overwrite with a non-existent signature algorithm type.
  token[9] = 0xff;

  SignedCertificateHash sch;
  EXPECT_FALSE(Deserializer::DeserializeSCHToken(token, &sch));
}

TEST_F(SerializerTest, DeserializeSCHTokenTooShort) {
  bstring token = B(kDefaultSCHTokenHexString, kDefaultSCHTokenLength);

  for (size_t i = 0; i < token.size(); ++i) {
    SignedCertificateHash sch;
    EXPECT_FALSE(Deserializer::DeserializeSCHToken(token.substr(0, i), &sch));
  }
}

TEST_F(SerializerTest, DeserializeSCHTokenTooLong) {
  bstring token = B(kDefaultSCHTokenHexString, kDefaultSCHTokenLength);
  token.push_back(0x42);

  SignedCertificateHash sch;

  // We can still read from the beginning of a longer string...
  Deserializer deserializer(token);
  EXPECT_TRUE(deserializer.ReadSCHToken(&sch));
  EXPECT_FALSE(deserializer.ReachedEnd());
  CompareSCHToken(DefaultSCH(), sch);

  // ... but we can't deserialize.
  EXPECT_FALSE(Deserializer::DeserializeSCHToken(token, &sch));
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
