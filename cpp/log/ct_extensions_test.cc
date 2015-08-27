#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>

#include "log/cert.h"
#include "log/ct_extensions.h"
#include "util/testing.h"
#include "util/util.h"

namespace cert_trans {

using std::string;

static const char kSimpleCert[] = "test-cert.pem";
static const char kSimpleCaCert[] = "ca-cert.pem";
static const char kFakeCertWithSCT[] = "test-cert-proof.pem";
static const char kCertWithPrecertSigning[] = "ca-pre-cert.pem";
static const char kCertWithPoison[] = "test-embedded-pre-cert.pem";
static const char kCertWithEmbeddedSCT[] = "test-embedded-cert.pem";

class CtExtensionsTest : public ::testing::Test {
 protected:
  string simple_cert_;
  string simple_ca_cert_;
  string sct_cert_;
  string pre_signing_cert_;
  string poison_cert_;
  string embedded_sct_cert_;

  void SetUp() {
    const string cert_dir(FLAGS_test_srcdir + "/test/testdata");
    CHECK(util::ReadTextFile(cert_dir + "/" + kSimpleCert, &simple_cert_))
        << "Could not read test data from " << cert_dir
        << ". Wrong --test_srcdir?";
    CHECK(
        util::ReadTextFile(cert_dir + "/" + kSimpleCaCert, &simple_ca_cert_));
    CHECK(util::ReadTextFile(cert_dir + "/" + kFakeCertWithSCT, &sct_cert_));
    CHECK(util::ReadTextFile(cert_dir + "/" + kCertWithPrecertSigning,
                             &pre_signing_cert_));
    CHECK(util::ReadTextFile(cert_dir + "/" + kCertWithPoison, &poison_cert_));
    CHECK(util::ReadTextFile(cert_dir + "/" + kCertWithEmbeddedSCT,
                             &embedded_sct_cert_));
  }
};

TEST_F(CtExtensionsTest, TestSCTExtension) {
  // Sanity check
  Cert simple_cert(simple_cert_);
  EXPECT_EQ(Cert::FALSE,
            simple_cert.HasExtension(
                cert_trans::NID_ctSignedCertificateTimestampList));

  Cert sct_cert(sct_cert_);
  // Check we can find the extension by its advertised NID.
  // We should really be checking that the OID matches the expected OID but
  // what other extension could this cert be having that the other one doesn't?
  ASSERT_EQ(Cert::TRUE, sct_cert.HasExtension(
                            cert_trans::NID_ctSignedCertificateTimestampList));

  string ext_data;
  EXPECT_EQ(Cert::TRUE,
            sct_cert.OctetStringExtensionData(
                cert_trans::NID_ctSignedCertificateTimestampList, &ext_data));
  EXPECT_FALSE(ext_data.empty());

  // Now fish the extension data out using the print methods and check they
  // operate as expected.
  // TODO(ekasper):
  X509_EXTENSION* ext;
  ASSERT_EQ(Cert::TRUE,
            sct_cert.GetExtension(
                cert_trans::NID_ctSignedCertificateTimestampList, &ext));
  BIO* buf = BIO_new(BIO_s_mem());
  ASSERT_NE(buf, static_cast<BIO*>(NULL));

  EXPECT_EQ(1, X509V3_EXT_print(buf, ext, 0, 0));
  CHECK_EQ(1, BIO_write(buf, "", 1));  // NULL-terminate
  char* result;
  BIO_get_mem_data(buf, &result);

  // Should be printing the octet string contents in hex.
  EXPECT_STRCASEEQ(util::HexString(ext_data, ':').c_str(), result);

  BIO_free(buf);
}

TEST_F(CtExtensionsTest, TestEmbeddedSCTExtension) {
  // Sanity check
  Cert simple_cert(simple_cert_);
  EXPECT_EQ(Cert::FALSE,
            simple_cert.HasExtension(
                cert_trans::NID_ctEmbeddedSignedCertificateTimestampList));

  Cert embedded_sct_cert(embedded_sct_cert_);
  ASSERT_TRUE(embedded_sct_cert.IsLoaded());
  // Check we can find the extension by its advertised NID.
  // We should really be checking that the OID matches the expected OID but
  // what other extension could this cert be having that the other one doesn't?
  ASSERT_EQ(Cert::TRUE,
            embedded_sct_cert.HasExtension(
                cert_trans::NID_ctEmbeddedSignedCertificateTimestampList));
  string ext_data;
  EXPECT_EQ(Cert::TRUE,
            embedded_sct_cert.OctetStringExtensionData(
                cert_trans::NID_ctEmbeddedSignedCertificateTimestampList,
                &ext_data));
  EXPECT_FALSE(ext_data.empty());

  // Now fish the extension data out using the print methods and check they
  // operate as expected.
  X509_EXTENSION* ext;
  ASSERT_EQ(Cert::TRUE,
            embedded_sct_cert.GetExtension(
                cert_trans::NID_ctEmbeddedSignedCertificateTimestampList,
                &ext));
  BIO* buf = BIO_new(BIO_s_mem());
  ASSERT_NE(buf, static_cast<BIO*>(NULL));

  EXPECT_EQ(1, X509V3_EXT_print(buf, ext, 0, 0));
  CHECK_EQ(1, BIO_write(buf, "", 1));  // NULL-terminate
  char* result;
  BIO_get_mem_data(buf, &result);

  // Should be printing the octet string contents in hex.
  EXPECT_STRCASEEQ(util::HexString(ext_data, ':').c_str(), result);

  BIO_free(buf);
}

TEST_F(CtExtensionsTest, TestPoisonExtension) {
  // Sanity check
  Cert simple_cert(simple_cert_);
  EXPECT_EQ(Cert::FALSE, simple_cert.HasExtension(cert_trans::NID_ctPoison));

  Cert poison_cert(poison_cert_);
  ASSERT_TRUE(poison_cert.IsLoaded());
  // Check we can find the extension by its advertised NID.
  // We should really be checking that the OID matches the expected OID but
  // what other extension could this cert be having that the other one doesn't?
  ASSERT_EQ(Cert::TRUE, poison_cert.HasExtension(cert_trans::NID_ctPoison));

  // Now fish the extension data out using the print methods and check they
  // operate as expected.
  X509_EXTENSION* ext;
  ASSERT_EQ(Cert::TRUE,
            poison_cert.GetExtension(cert_trans::NID_ctPoison, &ext));

  BIO* buf = BIO_new(BIO_s_mem());
  ASSERT_NE(buf, static_cast<BIO*>(NULL));

  EXPECT_EQ(1, X509V3_EXT_print(buf, ext, 0, 0));
  CHECK_EQ(1, BIO_write(buf, "", 1));  // NULL-terminate
  char* result;
  BIO_get_mem_data(buf, &result);

  // Should be printing "NULL".
  EXPECT_STREQ("NULL", result);

  BIO_free(buf);
}

TEST_F(CtExtensionsTest, TestPrecertSigning) {
  // Sanity check
  Cert simple_ca_cert(simple_ca_cert_);
  StatusOr<bool> simple_ca_eku_status = simple_ca_cert.HasExtendedKeyUsage(
      cert_trans::NID_ctPrecertificateSigning);
  EXPECT_TRUE(simple_ca_eku_status.ok() &&
              simple_ca_eku_status.ValueOrDie() == false);

  Cert pre_signing_cert(pre_signing_cert_);
  ASSERT_TRUE(pre_signing_cert.IsLoaded());
  // Check we can find the key usage by its advertised NID.
  // We should really be checking that the OID matches the expected OID but
  // what other key usage could this cert be having that the other one doesn't?
  StatusOr<bool> pre_signing_eku_status = pre_signing_cert.HasExtendedKeyUsage(
      cert_trans::NID_ctPrecertificateSigning);
  ASSERT_TRUE(pre_signing_eku_status.ok() &&
              pre_signing_eku_status.ValueOrDie());
}

}  // namespace cert_trans

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  OpenSSL_add_all_algorithms();
  cert_trans::LoadCtExtensions();
  return RUN_ALL_TESTS();
}
