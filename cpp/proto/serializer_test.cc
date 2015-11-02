/* -*- indent-tabs-mode: nil -*- */
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <google/protobuf/repeated_field.h>
#include <gtest/gtest.h>
#include <string>

#include "proto/ct.pb.h"
#include "proto/serializer.h"
#include "util/testing.h"
#include "util/util.h"

namespace {

using ct::DigitallySigned;
using ct::LogEntry;
using ct::LogEntryType;
using ct::MerkleTreeLeaf;
using ct::PrecertChainEntry;
using ct::SignedCertificateTimestamp;
using ct::SignedCertificateTimestampList;
using ct::SctExtension;
using ct::SignedTreeHead;
using ct::SthExtension;
using ct::Version;
using ct::X509ChainEntry;
using google::protobuf::RepeatedPtrField;
using std::string;

// A slightly shorter notation for constructing binary blobs from test vectors.
string B(const string& hexstring) {
  return util::BinaryString(hexstring);
}

// The reverse.
string H(const string& byte_string) {
  return util::HexString(byte_string);
}

// This string must be 32 bytes long to be a valid log id
static const char* kDUMMY_LOG_ID = "iamapublickeyshatwofivesixdigest";

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
    // keyid, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
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

const char kDefaultSCTHexStringV2[] =
    // version, 1 byte
    "01"
    // keyid, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
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

const char kDefaultSCTHexStringV2Extensions[] =
    // version, 1 byte
    "01"
    // keyid, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
    // timestamp, 8 bytes
    "00000000000004d2"
    // extensions count 2 bytes
    "0002"
    // extension 1 type
    "002a"
    // extension 1 data length
    "0009"
    // extension 1 data "dontpanic"
    "646f6e7470616e6963"
    // extension 2 type
    "0472"
    // extension 2 data length
    "0003"
    // extension 2 data "thx"
    "746878"
    // hash algo, sig algo, 2 bytes
    "0403"
    // signature length, 2 bytes
    "0009"
    // signature, 9 bytes
    "7369676e6174757265";

const char kDefaultSCTListHexString[] =
    // list length prefix
    "003a"
    // first (and only) SCT length prefix
    "0038"
    // the SCT
    "0069616d617075626c69636b657973686174776f666976657369786469676573740000000"
    "0000004d20000040300097369676e6174757265";

const char kDefaultCertSCTSignedHexString[] =
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

const char kDefaultCertSCTSignedHexStringExtensions[] =
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
    "0005"
    // extension data "hello"
    "68656c6c6f";

const char kDefaultCertSCTSignedHexStringV2[] =
    // version, 1 byte
    "01"
    // signature type, 1 byte
    "00"
    // timestamp, 8 bytes
    "00000000000004d2"
    // entry type, 2 bytes
    "0000"
    // keyid, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
    // leaf certificate length, 3 bytes
    "00000c"
    // leaf certificate, 12 bytes
    "636572746966696361746532"
    // extensions length, 2 bytes
    "0000";
    // extensions, 0 bytes

const char kDefaultCertSCTSignedHexStringV2Extensions[] =
    // version, 1 byte
    "01"
    // signature type, 1 byte
    "00"
    // timestamp, 8 bytes
    "00000000000004d2"
    // entry type, 2 bytes
    "0000"
    // keyid, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
    // leaf certificate length, 3 bytes
    "00000c"
    // leaf certificate, 12 bytes
    "636572746966696361746532"
    // extensions count 2 bytes
    "0002"
    // extension 1 type
    "002a"
    // extension 1 data length
    "0009"
    // extension 1 data "dontpanic"
    "646f6e7470616e6963"
    // extension 2 type
    "0472"
    // extension 2 data length
    "0003"
    // extension 2 data "thx"
    "746878";

const char kDefaultSignedCertEntryWithTypeHexString[] =
    // entry type, 2 bytes
    "0000"
    // leaf certificate length, 3 bytes
    "00000b"
    // leaf certificate, 11 bytes
    "6365727469666963617465";

const char kDefaultPrecertSCTSignedHexString[] =
    // version, 1 byte
    "00"
    // signature type, 1 byte
    "00"
    // timestamp, 8 bytes
    "00000000000004d2"
    // entry type, 2 bytes (PRECERT)
    "0001"
    // issuer key hash, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
    // tbs certificate length, 3 bytes
    "000003"
    // tbs certificate, 3 bytes
    "746273"
    // extensions length, 2 bytes
    "0000";
    // extensions, 0 bytes

const char kDefaultPrecertSCTSignedHexStringV2[] =
    // version, 1 byte
    "01"
    // signature type, 1 byte
    "00"
    // timestamp, 8 bytes
    "00000000000004d2"
    // entry type, 2 bytes (PRECERT_V2)
    "0002"
    // issuer key hash, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
    // certificate length, 4 bytes
    "000004"
    // certificate, 4 bytes
    "74627332"
    // extensions length, 2 bytes
    "0000";
    // extensions, 0 bytes

const char kDefaultSignedPrecertEntryWithTypeHexString[] =
    // entry type, 2 bytes
    "0001"
    // issuer key hash, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
    // tbs certificate length, 3 bytes
    "000003"
    // tbs certificate, 3 bytes
    "746273";

const char kDefaultCertSCTLeafHexString[] =
    // version, 1 byte
    "00"
    // leaf type, 1 byte
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

const char kDefaultCertSCTLeafHexStringV2[] =
    // version, 1 byte
    "01"
    // leaf type, 1 byte
    "00"
    // timestamp, 8 bytes
    "00000000000004d2"
    // entry type, 2 bytes
    "0000"
    // issuer key hash, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
    // leaf certificate length, 3 bytes
    "00000c"
    // leaf certificate, 12 bytes
    "636572746966696361746532"
    // extensions length, 2 bytes
    "0000";
    // extensions, 0 bytes

const char kDefaultCertSCTLeafHexStringV2Extensions[] =
    // version, 1 byte
    "01"
    // leaf type, 1 byte
    "00"
    // timestamp, 8 bytes
    "00000000000004d2"
    // entry type, 2 bytes
    "0000"
    // issuer key hash, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
    // leaf certificate length, 3 bytes
    "00000c"
    // leaf certificate, 12 bytes
    "636572746966696361746532"
    // extensions count 2 bytes
    "0002"
    // extension 1 type
    "002a"
    // extension 1 data length
    "0009"
    // extension 1 data "dontpanic"
    "646f6e7470616e6963"
    // extension 2 type
    "0472"
    // extension 2 data length
    "0003"
    // extension 2 data "thx"
    "746878";

const char kDefaultPrecertSCTLeafHexString[] =
    // version, 1 byte
    "00"
    // leaf type, 1 byte
    "00"
    // timestamp, 8 bytes
    "00000000000004d2"
    // entry type, 2 bytes (PRECERT)
    "0001"
    // issuer key hash, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
    // tbs certificate length, 3 bytes
    "000003"
    // leaf certificate, 3 bytes
    "746273"
    // extensions length, 2 bytes
    "0000";
    // extensions, 0 bytes

const char kDefaultPrecertSCTLeafHexStringV2[] =
    // version, 1 byte
    "01"
    // leaf type, 1 byte
    "00"
    // timestamp, 8 bytes
    "00000000000004d2"
    // entry type, 2 bytes (PRECERT_V2)
    "0002"
    // issuer key hash, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
    // tbs certificate length, 4 bytes
    "000004"
    // leaf certificate, 4 bytes
    "74627332"
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

const char kDefaultSTHSignedHexStringV2[] =
    // version, 1 byte
    "01"
    // signature type, 1 byte
    "01"
    // keyid, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
    // timestamp, 8 bytes
    "0000000000000929"
    // tree size, 8 bytes
    "0000000000000006"
    // root hash, 32 bytes
    "696d757374626565786163746c7974686972747974776f62797465736c6f6e67"
    // extensions length 2 bytes, no extension data
    "0000";

const char kDefaultSTHSignedHexStringV2Extensions[] =
    // version, 1 byte
    "01"
    // signature type, 1 byte
    "01"
    // keyid, 32 bytes
    "69616d617075626c69636b657973686174776f66697665736978646967657374"
    // timestamp, 8 bytes
    "0000000000000929"
    // tree size, 8 bytes
    "0000000000000006"
    // root hash, 32 bytes
    "696d757374626565786163746c7974686972747974776f62797465736c6f6e67"
    // extensions count 2 bytes
    "0002"
    // extension 1 type
    "002a"
    // extension 1 data length
    "0009"
    // extension 1 data "dontpanic"
    "646f6e7470616e6963"
    // extension 2 type
    "0472"
    // extension 2 data length
    "0003"
    // extension 2 data "thx"
    "746878";

// TODO(ekasper): switch to real data here, too.
class SerializerTest : public ::testing::Test {
 protected:
  SerializerTest()
      : cert_entry_(),
        cert_entry_v2_(),
        precert_entry_(),
        precert_entry_v2_(),
        sct_(),
        sct_v2_(),
        sct_v2_ext_(),
        sct_v2_ext_badorder_(),
        sct_list_(),
        sct_list_v2_(),
        sth_(),
        sth_v2_(),
        sth_v2_ext_(),
        sth_v2_ext_badorder_() {
    cert_entry_.set_type(ct::X509_ENTRY);
    cert_entry_.mutable_x509_entry()->set_leaf_certificate("certificate");

    cert_entry_v2_.set_type(ct::X509_ENTRY);
    cert_entry_v2_.mutable_x509_entry()
        ->mutable_cert_info()
        ->set_tbs_certificate("certificate2");
    cert_entry_v2_.mutable_x509_entry()
        ->mutable_cert_info()
        ->set_issuer_key_hash(kDUMMY_LOG_ID);

    precert_entry_.set_type(ct::PRECERT_ENTRY);
    precert_entry_.mutable_precert_entry()->set_pre_certificate("precert");
    precert_entry_.mutable_precert_entry()
        ->mutable_pre_cert()
        ->set_issuer_key_hash(kDUMMY_LOG_ID);
    precert_entry_.mutable_precert_entry()
        ->mutable_pre_cert()
        ->set_tbs_certificate("tbs");

    precert_entry_v2_.set_type(ct::PRECERT_ENTRY_V2);
    precert_entry_v2_.mutable_precert_entry()->set_pre_certificate("precert2");
    precert_entry_v2_.mutable_precert_entry()
        ->mutable_cert_info()
        ->set_issuer_key_hash(kDUMMY_LOG_ID);
    precert_entry_v2_.mutable_precert_entry()
        ->mutable_cert_info()
        ->set_tbs_certificate("tbs2");

    sct_.set_version(ct::V1);
    sct_.mutable_id()->set_key_id(kDUMMY_LOG_ID);
    sct_.set_timestamp(1234);
    sct_.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
    sct_.mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
    sct_.mutable_signature()->set_signature("signature");
    sct_list_.add_sct_list(B(kDefaultSCTHexString));

    sct_v2_.set_version(ct::V2);
    sct_v2_.mutable_id()->set_key_id(kDUMMY_LOG_ID);
    sct_v2_.set_timestamp(1234);
    sct_v2_.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
    sct_v2_.mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
    sct_v2_.mutable_signature()->set_signature("signature");
    sct_list_v2_.add_sct_list(B(kDefaultSCTHexStringV2));

    // create a v2 sct with extensions
    sct_v2_ext_ = sct_v2_;
    SctExtension* const sct_ext1 = sct_v2_ext_.add_sct_extension();
    sct_ext1->set_sct_extension_type(42);
    sct_ext1->set_sct_extension_data("dontpanic");

    SctExtension* const sct_ext2 = sct_v2_ext_.add_sct_extension();
    sct_ext2->set_sct_extension_type(1138);
    sct_ext2->set_sct_extension_data("thx");

    // create a v2 sct with extensions out of order and hence invalid
    sct_v2_ext_badorder_ = sct_v2_;
    SctExtension* const sct_ext1_bad =
        sct_v2_ext_badorder_.add_sct_extension();
    sct_ext1_bad->set_sct_extension_type(1138);
    sct_ext1_bad->set_sct_extension_data("thx");

    SctExtension* const sct_ext2_bad =
        sct_v2_ext_badorder_.add_sct_extension();
    sct_ext2_bad->set_sct_extension_type(42);
    sct_ext2_bad->set_sct_extension_data("dontpanic");

    sth_.set_version(ct::V1);
    sth_.mutable_id()->set_key_id(kDUMMY_LOG_ID);
    sth_.set_timestamp(2345);
    sth_.set_tree_size(6);
    sth_.set_sha256_root_hash("imustbeexactlythirtytwobyteslong");
    sth_.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
    sth_.mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
    sth_.mutable_signature()->set_signature("tree_signature");

    sth_v2_.set_version(ct::V2);
    sth_v2_.mutable_id()->set_key_id(kDUMMY_LOG_ID);
    sth_v2_.set_timestamp(2345);
    sth_v2_.set_tree_size(6);
    sth_v2_.set_sha256_root_hash("imustbeexactlythirtytwobyteslong");
    sth_v2_.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
    sth_v2_.mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
    sth_v2_.mutable_signature()->set_signature("tree_signature");

    sth_v2_ext_ = sth_v2_;  // basically the same but with added extensions
    SthExtension* const sth_ext1 = sth_v2_ext_.add_sth_extension();
    sth_ext1->set_sth_extension_type(42);
    sth_ext1->set_sth_extension_data("dontpanic");

    SthExtension* const sth_ext2 = sth_v2_ext_.add_sth_extension();
    sth_ext2->set_sth_extension_type(1138);
    sth_ext2->set_sth_extension_data("thx");

    // This sth has extensions out of order (invalid)
    sth_v2_ext_badorder_ = sth_v2_;
    SthExtension* const sth_ext1_bad_order =
        sth_v2_ext_badorder_.add_sth_extension();
    sth_ext1_bad_order->set_sth_extension_type(1138);
    sth_ext1_bad_order->set_sth_extension_data("thx");

    SthExtension* const sth_ext2_bad_order =
        sth_v2_ext_badorder_.add_sth_extension();
    sth_ext2_bad_order->set_sth_extension_type(42);
    sth_ext2_bad_order->set_sth_extension_data("dontpanic");
  }

  const LogEntry& DefaultCertEntry() const {
    return cert_entry_;
  }

  const LogEntry& DefaultCertEntryV2() const {
    return cert_entry_v2_;
  }

  const LogEntry& DefaultPrecertEntry() const {
    return precert_entry_;
  }

  const LogEntry& DefaultPrecertEntryV2() const {
    return precert_entry_v2_;
  }

  uint64_t DefaultSCTTimestamp() const {
    return sct_.timestamp();
  }

  string DefaultCertificate() const {
    return cert_entry_.x509_entry().leaf_certificate();
  }

  string DefaultCertificateV2() const {
    return cert_entry_v2_.x509_entry().cert_info().tbs_certificate();
  }

  string DefaultIssuerKeyHash() const {
    return precert_entry_.precert_entry().pre_cert().issuer_key_hash();
  }

  string DefaultTbsCertificate() const {
    return precert_entry_.precert_entry().pre_cert().tbs_certificate();
  }

  string DefaultTbsCertificateV2() const {
    return precert_entry_v2_.precert_entry().cert_info().tbs_certificate();
  }

  string DefaultExtensions() const {
    return string();
  }

  const RepeatedPtrField<SthExtension>& DefaultSthExtensions() const {
    return sth_v2_.sth_extension();
  }

  const SignedCertificateTimestamp& DefaultSCT() const {
    return sct_;
  }

  const SignedCertificateTimestamp& DefaultSCTV2() const {
    return sct_v2_;
  }

  const SignedCertificateTimestamp& DefaultSCTV2Ext() const {
    return sct_v2_ext_;
  }

  const RepeatedPtrField<SctExtension>& DefaultSctExtensions() const {
    return sct_v2_.sct_extension();
  }

  const SignedCertificateTimestamp& DefaultSCTV2ExtBadOrder() const {
    return sct_v2_ext_badorder_;
  }

  const SignedCertificateTimestampList& DefaultSCTList() const {
    return sct_list_;
  }

  const SignedCertificateTimestampList& DefaultSCTListV2() const {
    return sct_list_v2_;
  }

  uint64_t DefaultSTHTimestamp() const {
    return sth_.timestamp();
  }

  int64_t DefaultTreeSize() const {
    CHECK_GE(sth_.tree_size(), 0);
    return sth_.tree_size();
  }

  string DefaultRootHash() const {
    return sth_.sha256_root_hash();
  }

  const SignedTreeHead& DefaultSTH() const {
    return sth_;
  }

  const SignedTreeHead& DefaultSTHV2() const {
    return sth_v2_;
  }

  const SignedTreeHead& DefaultSTHV2Ext() const {
    return sth_v2_ext_;
  }

  const SignedTreeHead& DefaultSTHV2ExtBadOrder() const {
    return sth_v2_ext_badorder_;
  }

  const DigitallySigned& DefaultSCTSignature() const {
    return sct_.signature();
  }

  const DigitallySigned& DefaultSTHSignature() const {
    return sth_.signature();
  }

  static void CompareDS(const DigitallySigned& ds,
                        const DigitallySigned& ds2) {
    EXPECT_EQ(ds.hash_algorithm(), ds2.hash_algorithm());
    EXPECT_EQ(ds.sig_algorithm(), ds2.sig_algorithm());
    EXPECT_EQ(H(ds.signature()), H(ds2.signature()));
  }

  static void CompareSCT(const SignedCertificateTimestamp& sct,
                         const SignedCertificateTimestamp& sct2) {
    EXPECT_EQ(sct.version(), sct2.version());
    EXPECT_EQ(sct.id().key_id(), sct2.id().key_id());
    EXPECT_EQ(sct.timestamp(), sct2.timestamp());
    CompareDS(sct.signature(), sct2.signature());
  }

 private:
  LogEntry cert_entry_;
  LogEntry cert_entry_v2_;
  LogEntry precert_entry_;
  LogEntry precert_entry_v2_;
  SignedCertificateTimestamp sct_;
  SignedCertificateTimestamp sct_v2_;
  SignedCertificateTimestamp sct_v2_ext_;
  SignedCertificateTimestamp sct_v2_ext_badorder_;
  SignedCertificateTimestampList sct_list_;
  SignedCertificateTimestampList sct_list_v2_;
  SignedTreeHead sth_;
  SignedTreeHead sth_v2_;
  SignedTreeHead sth_v2_ext_;
  SignedTreeHead sth_v2_ext_badorder_;
};

TEST_F(SerializerTest, SerializeDigitallySignedKatTest) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeDigitallySigned(DefaultSCTSignature(),
                                                 &result));
  EXPECT_EQ(string(kDefaultSCTSignatureHexString), H(result));
}

TEST_F(SerializerTest, SerializeSCTKatTest) {
  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCT(DefaultSCT(), &result));
  EXPECT_EQ(string(kDefaultSCTHexString), H(result));
}

TEST_F(SerializerTest, SerializeSCTListKatTest) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTList(DefaultSCTList(), &result));
  EXPECT_EQ(string(kDefaultSCTListHexString), H(result));
}

TEST_F(SerializerTest, DeserializeSCTListKatTest) {
  SignedCertificateTimestampList sct_list;
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeSCTList(B(kDefaultSCTListHexString),
                                             &sct_list));
  EXPECT_EQ(1, sct_list.sct_list_size());
  EXPECT_EQ(string(kDefaultSCTHexString), H(sct_list.sct_list(0)));
}

TEST_F(SerializerTest, SerializeSCTSignatureInputKatTestV1) {
  string cert_result, precert_result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeV1CertSCTSignatureInput(
                                DefaultSCTTimestamp(), DefaultCertificate(),
                                DefaultExtensions(), &cert_result));
  EXPECT_EQ(string(kDefaultCertSCTSignedHexString), H(cert_result));

  EXPECT_EQ(Serializer::OK, Serializer::SerializeV1PrecertSCTSignatureInput(
                                DefaultSCTTimestamp(), DefaultIssuerKeyHash(),
                                DefaultTbsCertificate(), DefaultExtensions(),
                                &precert_result));
  EXPECT_EQ(string(kDefaultPrecertSCTSignedHexString), H(precert_result));

  EXPECT_NE(cert_result, precert_result);

  cert_result.clear();
  precert_result.clear();

  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTSignatureInput(DefaultSCT(),
                                                   DefaultCertEntry(),
                                                   &cert_result));
  EXPECT_EQ(string(kDefaultCertSCTSignedHexString), H(cert_result));

  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTSignatureInput(DefaultSCT(),
                                                   DefaultPrecertEntry(),
                                                   &precert_result));
  EXPECT_EQ(string(kDefaultPrecertSCTSignedHexString), H(precert_result));
}

TEST_F(SerializerTest, SerializeSCTSignatureInputKatTestV2) {
  string cert_result, precert_result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeV2CertSCTSignatureInput(
                DefaultSCTTimestamp(), DefaultIssuerKeyHash(),
                DefaultCertificateV2(), DefaultSctExtensions(), &cert_result));
  EXPECT_EQ(string(kDefaultCertSCTSignedHexStringV2), H(cert_result));

  EXPECT_EQ(Serializer::OK, Serializer::SerializeV2PrecertSCTSignatureInput(
                                DefaultSCTTimestamp(), DefaultIssuerKeyHash(),
                                DefaultTbsCertificateV2(),
                                DefaultSctExtensions(), &precert_result));
  EXPECT_EQ(string(kDefaultPrecertSCTSignedHexStringV2), H(precert_result));

  EXPECT_NE(cert_result, precert_result);

  cert_result.clear();
  precert_result.clear();

  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTSignatureInput(DefaultSCTV2(),
                                                   DefaultCertEntryV2(),
                                                   &cert_result));
  EXPECT_EQ(string(kDefaultCertSCTSignedHexStringV2), H(cert_result));

  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTSignatureInput(DefaultSCTV2(),
                                                   DefaultPrecertEntryV2(),
                                                   &precert_result));
  EXPECT_EQ(string(kDefaultPrecertSCTSignedHexStringV2), H(precert_result));
}

TEST_F(SerializerTest, SerializeSCTMerkleTreeLeafKatTestV1) {
  string cert_result, precert_result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeV1CertSCTMerkleTreeLeaf(
                                DefaultSCTTimestamp(), DefaultCertificate(),
                                DefaultExtensions(), &cert_result));
  EXPECT_EQ(string(kDefaultCertSCTLeafHexString), H(cert_result));

  EXPECT_EQ(Serializer::OK, Serializer::SerializeV1PrecertSCTMerkleTreeLeaf(
                                DefaultSCTTimestamp(), DefaultIssuerKeyHash(),
                                DefaultTbsCertificate(), DefaultExtensions(),
                                &precert_result));
  EXPECT_EQ(string(kDefaultPrecertSCTLeafHexString), H(precert_result));

  EXPECT_NE(cert_result, precert_result);

  cert_result.clear();
  precert_result.clear();

  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTMerkleTreeLeaf(DefaultSCT(),
                                                   DefaultCertEntry(),
                                                   &cert_result));
  EXPECT_EQ(string(kDefaultCertSCTLeafHexString), H(cert_result));

  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTMerkleTreeLeaf(DefaultSCT(),
                                                   DefaultPrecertEntry(),
                                                   &precert_result));
  EXPECT_EQ(string(kDefaultPrecertSCTLeafHexString), H(precert_result));
}

TEST_F(SerializerTest, SerializeSCTMerkleTreeLeafKatTestV2) {
  string cert_result, precert_result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeV2CertSCTMerkleTreeLeaf(
                DefaultSCTTimestamp(), DefaultIssuerKeyHash(),
                DefaultCertificateV2(), DefaultSctExtensions(), &cert_result));
  EXPECT_EQ(string(kDefaultCertSCTLeafHexStringV2), H(cert_result));

  EXPECT_EQ(Serializer::OK, Serializer::SerializeV2PrecertSCTMerkleTreeLeaf(
                                DefaultSCTTimestamp(), DefaultIssuerKeyHash(),
                                DefaultTbsCertificateV2(),
                                DefaultSctExtensions(), &precert_result));
  EXPECT_EQ(string(kDefaultPrecertSCTLeafHexStringV2), H(precert_result));

  EXPECT_NE(cert_result, precert_result);

  cert_result.clear();
  precert_result.clear();

  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTMerkleTreeLeaf(DefaultSCTV2(),
                                                   DefaultCertEntryV2(),
                                                   &cert_result));
  EXPECT_EQ(string(kDefaultCertSCTLeafHexStringV2), H(cert_result));

  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTMerkleTreeLeaf(DefaultSCTV2(),
                                                   DefaultPrecertEntryV2(),
                                                   &precert_result));
  EXPECT_EQ(string(kDefaultPrecertSCTLeafHexStringV2), H(precert_result));
}

TEST_F(SerializerTest, DeserializeMerkleTreeLeafKATV1Cert) {
  MerkleTreeLeaf leaf;
  EXPECT_EQ(Deserializer::OK, Deserializer::DeserializeMerkleTreeLeaf(
                                  B(kDefaultCertSCTLeafHexString), &leaf));
  EXPECT_EQ(leaf.version(), ct::V1);
  EXPECT_EQ(leaf.type(), ct::TIMESTAMPED_ENTRY);
  EXPECT_EQ(leaf.timestamped_entry().timestamp(), DefaultSCTTimestamp());
  EXPECT_EQ(leaf.timestamped_entry().entry_type(), ct::X509_ENTRY);
  EXPECT_EQ(leaf.timestamped_entry().signed_entry().x509(),
            DefaultCertEntry().x509_entry().leaf_certificate());
  EXPECT_FALSE(leaf.timestamped_entry().signed_entry().has_precert());
}

TEST_F(SerializerTest, DeserializeMerkleTreeLeafKATV1Precert) {
  MerkleTreeLeaf leaf;
  EXPECT_EQ(Deserializer::OK, Deserializer::DeserializeMerkleTreeLeaf(
                                  B(kDefaultPrecertSCTLeafHexString), &leaf));
  EXPECT_EQ(leaf.version(), ct::V1);
  EXPECT_EQ(leaf.type(), ct::TIMESTAMPED_ENTRY);
  EXPECT_EQ(leaf.timestamped_entry().timestamp(), DefaultSCTTimestamp());
  EXPECT_EQ(leaf.timestamped_entry().entry_type(), ct::PRECERT_ENTRY);
  EXPECT_FALSE(leaf.timestamped_entry().signed_entry().has_x509());
  EXPECT_EQ(
      leaf.timestamped_entry().signed_entry().precert().issuer_key_hash(),
      DefaultIssuerKeyHash());
  EXPECT_EQ(
      leaf.timestamped_entry().signed_entry().precert().tbs_certificate(),
      DefaultTbsCertificate());
}

TEST_F(SerializerTest, DeserializeMerkleTreeLeafKATV2Cert) {
  MerkleTreeLeaf leaf;
  EXPECT_EQ(Deserializer::OK, Deserializer::DeserializeMerkleTreeLeaf(
                                  B(kDefaultCertSCTLeafHexStringV2), &leaf));
  EXPECT_EQ(leaf.version(), ct::V2);
  EXPECT_EQ(leaf.type(), ct::TIMESTAMPED_ENTRY);
  EXPECT_EQ(leaf.timestamped_entry().timestamp(), DefaultSCTTimestamp());
  EXPECT_EQ(leaf.timestamped_entry().entry_type(), ct::X509_ENTRY);
  EXPECT_EQ(
      leaf.timestamped_entry().signed_entry().cert_info().tbs_certificate(),
      DefaultCertEntryV2().x509_entry().cert_info().tbs_certificate());
  EXPECT_EQ(
      leaf.timestamped_entry().signed_entry().cert_info().issuer_key_hash(),
      DefaultCertEntryV2().x509_entry().cert_info().issuer_key_hash());
  EXPECT_FALSE(leaf.timestamped_entry().signed_entry().has_precert());
}

TEST_F(SerializerTest, DeserializeMerkleTreeLeafKATV2Precert) {
  MerkleTreeLeaf leaf;
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeMerkleTreeLeaf(
                B(kDefaultPrecertSCTLeafHexStringV2), &leaf));
  EXPECT_EQ(leaf.version(), ct::V2);
  EXPECT_EQ(leaf.type(), ct::TIMESTAMPED_ENTRY);
  EXPECT_EQ(leaf.timestamped_entry().timestamp(), DefaultSCTTimestamp());
  EXPECT_EQ(leaf.timestamped_entry().entry_type(), ct::PRECERT_ENTRY_V2);
  EXPECT_FALSE(leaf.timestamped_entry().signed_entry().has_x509());
  EXPECT_EQ(
      leaf.timestamped_entry().signed_entry().cert_info().issuer_key_hash(),
      DefaultIssuerKeyHash());
  EXPECT_EQ(
      leaf.timestamped_entry().signed_entry().cert_info().tbs_certificate(),
      DefaultTbsCertificateV2());
}

TEST_F(SerializerTest, DeserializeSCTKatTestV1) {
  string token = B(kDefaultSCTHexString);
  SignedCertificateTimestamp sct;
  EXPECT_EQ(Deserializer::OK, Deserializer::DeserializeSCT(token, &sct));
  CompareSCT(DefaultSCT(), sct);
}

TEST_F(SerializerTest, DeserializeSCTKatTestV2) {
  string token = B(kDefaultSCTHexStringV2);
  SignedCertificateTimestamp sct;
  EXPECT_EQ(Deserializer::OK, Deserializer::DeserializeSCT(token, &sct));
  CompareSCT(DefaultSCTV2(), sct);
}

TEST_F(SerializerTest, DeserializeDigitallySignedKatTest) {
  string serialized_sig = B(kDefaultSCTSignatureHexString);
  DigitallySigned signature;
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeDigitallySigned(serialized_sig,
                                                     &signature));
  CompareDS(DefaultSCTSignature(), signature);
}

TEST_F(SerializerTest, SerializeDeserializeSCTChangeHashAlgorithm) {
  SignedCertificateTimestamp sct(DefaultSCT());
  sct.mutable_signature()->set_hash_algorithm(DigitallySigned::SHA224);

  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCT(sct, &result));

  string default_result = string(kDefaultSCTHexString);
  string new_result = H(result);
  EXPECT_EQ(default_result.size(), new_result.size());
  EXPECT_NE(default_result, new_result);

  SignedCertificateTimestamp read_sct;
  EXPECT_EQ(Deserializer::OK, Deserializer::DeserializeSCT(result, &read_sct));
  CompareSCT(read_sct, sct);
}

TEST_F(SerializerTest, SerializeDeserializeSCTChangeSignature) {
  SignedCertificateTimestamp sct(DefaultSCT());
  sct.mutable_signature()->set_signature("bazinga");

  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCT(sct, &result));
  EXPECT_NE(string(kDefaultSCTHexString), H(result));

  SignedCertificateTimestamp read_sct;
  EXPECT_EQ(Deserializer::OK, Deserializer::DeserializeSCT(result, &read_sct));
  CompareSCT(read_sct, sct);
}

TEST_F(SerializerTest, SerializeSCTSignatureInputEmptyCertificate) {
  string result;
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeV1CertSCTSignatureInput(DefaultSCTTimestamp(),
                                                         string(),
                                                         DefaultExtensions(),
                                                         &result));

  LogEntry entry(DefaultCertEntry());
  entry.mutable_x509_entry()->clear_leaf_certificate();
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeSCTSignatureInput(DefaultSCT(), entry,
                                                   &result));
}

TEST_F(SerializerTest, SerializeSCTMerkleTreeLeafEmptyCertificate) {
  string result;
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeV1CertSCTMerkleTreeLeaf(DefaultSCTTimestamp(),
                                                         string(),
                                                         DefaultExtensions(),
                                                         &result));

  LogEntry entry(DefaultCertEntry());
  entry.mutable_x509_entry()->clear_leaf_certificate();
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeSCTMerkleTreeLeaf(DefaultSCT(), entry,
                                                   &result));
}

TEST_F(SerializerTest, SerializeSCTSignatureInputEmptyTbsCertificate) {
  string result;
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeV1PrecertSCTSignatureInput(
                DefaultSCTTimestamp(), DefaultIssuerKeyHash(), string(),
                DefaultExtensions(), &result));

  LogEntry entry(DefaultPrecertEntry());
  entry.mutable_precert_entry()->mutable_pre_cert()->clear_tbs_certificate();
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeSCTSignatureInput(DefaultSCT(), entry,
                                                   &result));
}

TEST_F(SerializerTest, SerializeSCTMerkleTreeLeafEmptyTbsCertificate) {
  string result;
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeV1PrecertSCTMerkleTreeLeaf(
                DefaultSCTTimestamp(), DefaultIssuerKeyHash(), string(),
                DefaultExtensions(), &result));

  LogEntry entry(DefaultPrecertEntry());
  entry.mutable_precert_entry()->mutable_pre_cert()->clear_tbs_certificate();
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeSCTMerkleTreeLeaf(DefaultSCT(), entry,
                                                   &result));
}

TEST_F(SerializerTest, SerializeSCTSignatureInputInvalidIssuerKeyHash) {
  string result;
  EXPECT_EQ(Serializer::INVALID_HASH_LENGTH,
            Serializer::SerializeV1PrecertSCTSignatureInput(
                DefaultSCTTimestamp(), "hash" /* not 32 bytes */,
                DefaultTbsCertificate(), DefaultExtensions(), &result));

  LogEntry entry(DefaultPrecertEntry());
  entry.mutable_precert_entry()->mutable_pre_cert()->set_issuer_key_hash("sh");
  EXPECT_EQ(Serializer::INVALID_HASH_LENGTH,
            Serializer::SerializeSCTSignatureInput(DefaultSCT(), entry,
                                                   &result));
}

TEST_F(SerializerTest, SerializeSCTMerkleTreeLeafInvalidIssuerKeyHash) {
  string result;
  EXPECT_EQ(Serializer::INVALID_HASH_LENGTH,
            Serializer::SerializeV1PrecertSCTMerkleTreeLeaf(
                DefaultSCTTimestamp(), "hash" /* not 32 bytes */,
                DefaultTbsCertificate(), DefaultExtensions(), &result));

  LogEntry entry(DefaultPrecertEntry());
  entry.mutable_precert_entry()->mutable_pre_cert()->set_issuer_key_hash("sh");
  EXPECT_EQ(Serializer::INVALID_HASH_LENGTH,
            Serializer::SerializeSCTMerkleTreeLeaf(DefaultSCT(), entry,
                                                   &result));
}

TEST_F(SerializerTest, DeserializeSCTBadHashType) {
  string token = B(kDefaultSCTHexString);
  // Overwrite with a non-existent hash algorithm type.
  token[43] = 0xff;

  SignedCertificateTimestamp sct;
  EXPECT_EQ(Deserializer::INVALID_HASH_ALGORITHM,
            Deserializer::DeserializeSCT(token, &sct));
}

TEST_F(SerializerTest, DeserializeSCTBadSignatureType) {
  string token = B(kDefaultSCTHexString);
  // Overwrite with a non-existent signature algorithm type.
  token[44] = 0xff;

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

TEST_F(SerializerTest, SerializeSTHSignatureInputKatTestV1) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSTHSignatureInput(DefaultSTH(), &result));
  EXPECT_EQ(string(kDefaultSTHSignedHexString), H(result));

  result.clear();
  EXPECT_EQ(Serializer::OK, Serializer::SerializeV1STHSignatureInput(
                                DefaultSTHTimestamp(), DefaultTreeSize(),
                                DefaultRootHash(), &result));
  EXPECT_EQ(string(kDefaultSTHSignedHexString), H(result));
}

TEST_F(SerializerTest, SerializeSTHSignatureInputKatTestV2) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSTHSignatureInput(DefaultSTHV2(), &result));
  EXPECT_EQ(string(kDefaultSTHSignedHexStringV2), H(result));

  result.clear();
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeV2STHSignatureInput(
                DefaultSTHTimestamp(), DefaultTreeSize(), DefaultRootHash(),
                DefaultSthExtensions(), kDUMMY_LOG_ID, &result));
  EXPECT_EQ(string(kDefaultSTHSignedHexStringV2), H(result));
}

TEST_F(SerializerTest, SerializeSTHSignatureInputKatTestV2InvalidLogId) {
  string result;
  EXPECT_EQ(Serializer::INVALID_KEYID_LENGTH,
            Serializer::SerializeV2STHSignatureInput(
                DefaultSTHTimestamp(), DefaultTreeSize(), DefaultRootHash(),
                DefaultSthExtensions(), "this isn't 32 bytes long", &result));
}

TEST_F(SerializerTest, SerializeSTHSignatureInputKatTestV2WithExtensions) {
  string result;
  SignedTreeHead sth(DefaultSTHV2Ext());
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSTHSignatureInput(sth, &result));
  EXPECT_EQ(string(kDefaultSTHSignedHexStringV2Extensions), H(result));

  result.clear();
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeV2STHSignatureInput(
                DefaultSTHTimestamp(), DefaultTreeSize(), DefaultRootHash(),
                DefaultSTHV2Ext().sth_extension(), kDUMMY_LOG_ID, &result));
  EXPECT_EQ(string(kDefaultSTHSignedHexStringV2Extensions), H(result));
}

TEST_F(SerializerTest, SerializeSTHSignatureInputBadHashV1) {
  SignedTreeHead sth(DefaultSTH());
  sth.set_sha256_root_hash("thisisnotthirtytwobyteslong");
  string result;
  EXPECT_EQ(Serializer::INVALID_HASH_LENGTH,
            Serializer::SerializeSTHSignatureInput(sth, &result));
}

TEST_F(SerializerTest, SerializeSTHSignatureInputBadHashV2) {
  SignedTreeHead sth(DefaultSTHV2());
  sth.set_sha256_root_hash("thisisnotthirtytwobyteslong");
  string result;
  EXPECT_EQ(Serializer::INVALID_HASH_LENGTH,
            Serializer::SerializeSTHSignatureInput(sth, &result));
}

TEST_F(SerializerTest, SerializeSTHSignatureInputExtBadOrderV2) {
  string result;
  EXPECT_EQ(Serializer::EXTENSIONS_NOT_ORDERED,
            Serializer::SerializeSTHSignatureInput(DefaultSTHV2ExtBadOrder(),
                                                   &result));
}

TEST_F(SerializerTest, SerializeSCTWithExtensionsTestV1) {
  SignedCertificateTimestamp sct(DefaultSCT());
  sct.set_extensions("hello");
  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCT(sct, &result));
  EXPECT_NE(string(kDefaultSCTHexString), H(result));
}

TEST_F(SerializerTest, SerializeSCTWithExtensionsTestV2) {
  SignedCertificateTimestamp sct(DefaultSCTV2Ext());
  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCT(sct, &result));
  EXPECT_EQ(string(kDefaultSCTHexStringV2Extensions), H(result));
}

TEST_F(SerializerTest, SerializeSCTWithExtensionsTestV2BadOrder) {
  SignedCertificateTimestamp sct(DefaultSCTV2ExtBadOrder());
  string result;
  EXPECT_EQ(Serializer::EXTENSIONS_NOT_ORDERED,
            Serializer::SerializeSCT(sct, &result));
}

TEST_F(SerializerTest, SerializeSCTSignatureInputWithExtensionsTestV1) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeV1CertSCTSignatureInput(DefaultSCTTimestamp(),
                                                         DefaultCertificate(),
                                                         "hello", &result));
  EXPECT_EQ(string(kDefaultCertSCTSignedHexStringExtensions), H(result));

  result.clear();
  SignedCertificateTimestamp sct(DefaultSCT());
  sct.set_extensions("hello");
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTSignatureInput(sct, DefaultCertEntry(),
                                                   &result));
  EXPECT_EQ(string(kDefaultCertSCTSignedHexStringExtensions), H(result));
}

TEST_F(SerializerTest, SerializeSCTSignatureInputWithExtensionsTestV2) {
  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeV2CertSCTSignatureInput(
                                DefaultSCTTimestamp(), DefaultIssuerKeyHash(),
                                DefaultCertificateV2(),
                                DefaultSCTV2Ext().sct_extension(), &result));
  EXPECT_EQ(string(kDefaultCertSCTSignedHexStringV2Extensions), H(result));

  result.clear();
  SignedCertificateTimestamp sct(DefaultSCTV2Ext());
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTSignatureInput(sct, DefaultCertEntryV2(),
                                                   &result));
  EXPECT_EQ(string(kDefaultCertSCTSignedHexStringV2Extensions), H(result));
}

TEST_F(SerializerTest, SerializeSCTMerkleTreeLeafWithExtensionsTestV1) {
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeV1CertSCTMerkleTreeLeaf(DefaultSCTTimestamp(),
                                                         DefaultCertificate(),
                                                         "hello", &result));
  EXPECT_NE(string(kDefaultCertSCTLeafHexString), H(result));

  result.clear();
  SignedCertificateTimestamp sct(DefaultSCT());
  sct.set_extensions("hello");
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTMerkleTreeLeaf(sct, DefaultCertEntry(),
                                                   &result));
  EXPECT_NE(string(kDefaultCertSCTLeafHexString), H(result));
}

TEST_F(SerializerTest, SerializeSCTMerkleTreeLeafWithExtensionsTestV2) {
  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeV2CertSCTMerkleTreeLeaf(
                                DefaultSCTTimestamp(), DefaultIssuerKeyHash(),
                                DefaultCertificateV2(),
                                DefaultSCTV2Ext().sct_extension(), &result));
  EXPECT_EQ(string(kDefaultCertSCTLeafHexStringV2Extensions), H(result));

  result.clear();
  SignedCertificateTimestamp sct(DefaultSCTV2Ext());
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeSCTMerkleTreeLeaf(sct, DefaultCertEntryV2(),
                                                   &result));
  EXPECT_EQ(string(kDefaultCertSCTLeafHexStringV2Extensions), H(result));
}

TEST_F(SerializerTest, SerializeDeserializeSCTAddExtensionsV1) {
  SignedCertificateTimestamp sct(DefaultSCT());
  sct.set_extensions("hello");

  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCT(sct, &result));

  SignedCertificateTimestamp read_sct;
  EXPECT_EQ(Deserializer::OK, Deserializer::DeserializeSCT(result, &read_sct));
  CompareSCT(sct, read_sct);
}

TEST_F(SerializerTest, SerializeDeserializeSCTAddExtensionsV2) {
  SignedCertificateTimestamp sct(DefaultSCTV2Ext());

  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCT(sct, &result));

  SignedCertificateTimestamp read_sct;
  EXPECT_EQ(Deserializer::OK, Deserializer::DeserializeSCT(result, &read_sct));
  CompareSCT(sct, read_sct);
}

TEST_F(SerializerTest, SerializeSCTUnsupportedVersion) {
  SignedCertificateTimestamp sct(DefaultSCT());
  sct.set_version(ct::UNKNOWN_VERSION);

  string result;
  EXPECT_EQ(Serializer::UNSUPPORTED_VERSION,
            Serializer::SerializeSCT(sct, &result));
}

TEST_F(SerializerTest, SerializeSCTSignatureInputUnsupportedVersion) {
  SignedCertificateTimestamp sct(DefaultSCT());
  sct.set_version(ct::UNKNOWN_VERSION);

  string result;
  EXPECT_EQ(Serializer::UNSUPPORTED_VERSION,
            Serializer::SerializeSCTSignatureInput(sct, DefaultCertEntry(),
                                                   &result));
}

TEST_F(SerializerTest, SerializeSCTMerkleTreeLeafUnsupportedVersion) {
  SignedCertificateTimestamp sct(DefaultSCT());
  sct.set_version(ct::UNKNOWN_VERSION);

  string result;
  EXPECT_EQ(Serializer::UNSUPPORTED_VERSION,
            Serializer::SerializeSCTMerkleTreeLeaf(sct, DefaultCertEntry(),
                                                   &result));
}

TEST_F(SerializerTest, SerializeSTHSignatureInputUnsupportedVersion) {
  SignedTreeHead sth(DefaultSTH());
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

TEST_F(SerializerTest, SerializeEmptySCTList) {
  SignedCertificateTimestampList sct_list;
  string result;
  EXPECT_EQ(Serializer::EMPTY_LIST,
            Serializer::SerializeSCTList(sct_list, &result));
}

TEST_F(SerializerTest, DeserializeEmptySCTList) {
  // Length prefix for an empty list.
  string empty_hex = "0000";
  SignedCertificateTimestampList sct_list;
  string result;
  EXPECT_EQ(Deserializer::EMPTY_LIST,
            Deserializer::DeserializeSCTList(B(empty_hex), &sct_list));
}

TEST_F(SerializerTest, SerializeSCTListEmptySCTInList) {
  SignedCertificateTimestampList sct_list;
  sct_list.add_sct_list(B(kDefaultSCTHexString));
  sct_list.add_sct_list(string());
  string result;
  EXPECT_EQ(Serializer::EMPTY_ELEM_IN_LIST,
            Serializer::SerializeSCTList(sct_list, &result));
}

TEST_F(SerializerTest, DeserializeSCTListEmptySCTInList) {
  // Length prefix for a list with an empty sct.
  string empty_hex = "00020000";
  SignedCertificateTimestampList sct_list;
  string result;
  EXPECT_EQ(Deserializer::EMPTY_ELEM_IN_LIST,
            Deserializer::DeserializeSCTList(B(empty_hex), &sct_list));
}

TEST_F(SerializerTest, SerializeDeserializeMultiSCTList) {
  SignedCertificateTimestampList sct_list;
  sct_list.add_sct_list("hello");
  sct_list.add_sct_list(B(kDefaultSCTHexString));
  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeSCTList(sct_list, &result));
  SignedCertificateTimestampList read_sct_list;
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeSCTList(result, &read_sct_list));
  EXPECT_EQ(2, read_sct_list.sct_list_size());
  EXPECT_EQ("hello", read_sct_list.sct_list(0));
  EXPECT_EQ(B(kDefaultSCTHexString), read_sct_list.sct_list(1));
}

TEST_F(SerializerTest, DeserializeSCTListTooLong) {
  string sct_string(B(kDefaultSCTListHexString));
  sct_string.push_back('x');
  SignedCertificateTimestampList read_sct_list;
  EXPECT_EQ(Deserializer::INPUT_TOO_LONG,
            Deserializer::DeserializeSCTList(sct_string, &read_sct_list));
}

TEST_F(SerializerTest, DeserializeSCTListTooShort) {
  string sct_string(B(kDefaultSCTListHexString));
  string bad_string(sct_string.substr(0, sct_string.size() - 1));
  SignedCertificateTimestampList read_sct_list;
  EXPECT_EQ(Deserializer::INPUT_TOO_SHORT,
            Deserializer::DeserializeSCTList(bad_string, &read_sct_list));
}

TEST_F(SerializerTest, DeserializeSCTListInvalidList) {
  // 2 byte-list, length of the first element allegedly 1 bytes...
  string invalid_hex = "00020001";
  SignedCertificateTimestampList read_sct_list;
  EXPECT_EQ(Deserializer::INVALID_LIST_ENCODING,
            Deserializer::DeserializeSCTList(B(invalid_hex), &read_sct_list));
}

TEST_F(SerializerTest, SerializeDeserializeX509Chain) {
  X509ChainEntry entry, read_entry;
  entry.set_leaf_certificate("cert");
  entry.add_certificate_chain("hello");
  entry.add_certificate_chain("world");
  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeX509Chain(entry, &result));
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeX509Chain(result, &read_entry));
  // TODO(ekasper): proper KAT tests
  EXPECT_EQ(2, read_entry.certificate_chain_size());
  EXPECT_EQ("hello", read_entry.certificate_chain(0));
  EXPECT_EQ("world", read_entry.certificate_chain(1));
  // Leaf cert does not get written or read.
  EXPECT_FALSE(read_entry.has_leaf_certificate());
}

TEST_F(SerializerTest, SerializeDeserializeX509Chain_EmptyChain) {
  X509ChainEntry entry, read_entry;
  string result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeX509Chain(entry, &result));
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializeX509Chain(result, &read_entry));
  EXPECT_EQ(0, read_entry.certificate_chain_size());
}

TEST_F(SerializerTest, SerializeDeserializeX509Chain_EmptyCert) {
  X509ChainEntry entry, read_entry;
  entry.add_certificate_chain("");

  string result;
  EXPECT_EQ(Serializer::EMPTY_ELEM_IN_LIST,
            Serializer::SerializeX509Chain(entry, &result));
}

TEST_F(SerializerTest, SerializeDeserializePrecertChainEntry) {
  PrecertChainEntry entry, read_entry;
  entry.set_pre_certificate("hello");
  entry.add_precertificate_chain("world");
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializePrecertChainEntry(entry, &result));
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializePrecertChainEntry(result, &read_entry));
  // TODO(ekasper): proper KAT tests
  EXPECT_EQ(1, read_entry.precertificate_chain_size());
  EXPECT_EQ("hello", read_entry.pre_certificate());
  EXPECT_EQ("world", read_entry.precertificate_chain(0));
}

TEST_F(SerializerTest, SerializeDeserializePrecertChainEntry_EmptyPrecert) {
  PrecertChainEntry entry, read_entry;
  entry.add_precertificate_chain("world");
  string result;
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializePrecertChainEntry(entry, &result));
}

TEST_F(SerializerTest, SerializeDeserializePrecertChainEntry_EmptyChain) {
  PrecertChainEntry entry, read_entry;
  entry.set_pre_certificate("hello");
  string result;
  EXPECT_EQ(Serializer::OK,
            Serializer::SerializePrecertChainEntry(entry, &result));
  EXPECT_EQ(Deserializer::OK,
            Deserializer::DeserializePrecertChainEntry(result, &read_entry));
  EXPECT_EQ(0, read_entry.precertificate_chain_size());
  EXPECT_EQ("hello", read_entry.pre_certificate());
}

TEST_F(SerializerTest, SerializeDeserializePrecertChainEntry_EmptyChainCert) {
  PrecertChainEntry entry, read_entry;
  entry.set_pre_certificate("hello");
  entry.add_precertificate_chain("");
  string result;
  EXPECT_EQ(Serializer::EMPTY_ELEM_IN_LIST,
            Serializer::SerializePrecertChainEntry(entry, &result));
}

TEST_F(SerializerTest, SerializeSCTSignedEntryWithType_KatTest) {
  string cert_result, precert_result;
  EXPECT_EQ(Serializer::OK, Serializer::SerializeV1SignedCertEntryWithType(
                                DefaultCertificate(), &cert_result));
  EXPECT_EQ(string(kDefaultSignedCertEntryWithTypeHexString), H(cert_result));

  EXPECT_EQ(Serializer::OK, Serializer::SerializeV1SignedPrecertEntryWithType(
                                DefaultIssuerKeyHash(),
                                DefaultTbsCertificate(), &precert_result));
  EXPECT_EQ(string(kDefaultSignedPrecertEntryWithTypeHexString),
            H(precert_result));

  cert_result.clear();
  precert_result.clear();

  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeV1SignedEntryWithType(DefaultCertEntry(),
                                                       &cert_result));
  EXPECT_EQ(string(kDefaultSignedCertEntryWithTypeHexString), H(cert_result));

  EXPECT_EQ(Serializer::OK,
            Serializer::SerializeV1SignedEntryWithType(DefaultPrecertEntry(),
                                                       &precert_result));
  EXPECT_EQ(string(kDefaultSignedPrecertEntryWithTypeHexString),
            H(precert_result));
}

TEST_F(SerializerTest, SerializeSCTSignedEntryWithType_EmptyCertificate) {
  string result;
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeV1SignedCertEntryWithType(string(), &result));

  LogEntry entry(DefaultCertEntry());
  entry.mutable_x509_entry()->clear_leaf_certificate();
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeV1SignedEntryWithType(entry, &result));
}

TEST_F(SerializerTest, SerializeSCTSignedEntryWithType_EmptyTbsCertificate) {
  string result;
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeV1SignedPrecertEntryWithType(
                DefaultIssuerKeyHash(), string(), &result));

  LogEntry entry(DefaultPrecertEntry());
  entry.mutable_precert_entry()->mutable_pre_cert()->clear_tbs_certificate();
  EXPECT_EQ(Serializer::EMPTY_CERTIFICATE,
            Serializer::SerializeV1SignedEntryWithType(entry, &result));
}

TEST_F(SerializerTest, SerializeSCTSignedEntryWithType_BadIssuerKeyHash) {
  string result;
  EXPECT_EQ(Serializer::INVALID_HASH_LENGTH,
            Serializer::SerializeV1SignedPrecertEntryWithType(
                "bad", DefaultTbsCertificate(), &result));

  LogEntry entry(DefaultPrecertEntry());
  entry.mutable_precert_entry()->mutable_pre_cert()->set_issuer_key_hash(
      "bad");
  EXPECT_EQ(Serializer::INVALID_HASH_LENGTH,
            Serializer::SerializeV1SignedEntryWithType(entry, &result));
}

}  // namespace

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
