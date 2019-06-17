#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>

#include "log/cert.h"
#include "log/ct_extensions.h"
#include "util/openssl_scoped_types.h"
#include "util/status_test_util.h"
#include "util/testing.h"
#include "util/util.h"

namespace cert_trans {

using std::string;
using std::unique_ptr;
using util::StatusOr;

static const char kSimpleCert[] = "test-cert.pem";
static const char kSimpleCaCert[] = "ca-cert.pem";
static const char kCertWithPrecertSigning[] = "ca-pre-cert.pem";
static const char kCertWithPoison[] = "test-embedded-pre-cert.pem";
static const char kCertWithEmbeddedSCT[] = "test-embedded-cert.pem";

class CtExtensionsTest : public ::testing::Test {
 protected:
  string simple_cert_;
  string simple_ca_cert_;
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
    CHECK(util::ReadTextFile(cert_dir + "/" + kCertWithPrecertSigning,
                             &pre_signing_cert_));
    CHECK(util::ReadTextFile(cert_dir + "/" + kCertWithPoison, &poison_cert_));
    CHECK(util::ReadTextFile(cert_dir + "/" + kCertWithEmbeddedSCT,
                             &embedded_sct_cert_));
  }
};

TEST_F(CtExtensionsTest, TestEmbeddedSCTExtension) {
  // Sanity check
  const unique_ptr<Cert> simple_cert(Cert::FromPemString(simple_cert_));
  ASSERT_TRUE(simple_cert.get());
  EXPECT_FALSE(
      simple_cert
          ->HasExtension(
              NID_ct_precert_scts)
          .ValueOrDie());

  const unique_ptr<Cert> embedded_sct_cert(
      Cert::FromPemString(embedded_sct_cert_));
  ASSERT_TRUE(embedded_sct_cert.get());
  // Check we can find the extension by its advertised NID.
  // We should really be checking that the OID matches the expected OID but
  // what other extension could this cert be having that the other one doesn't?
  ASSERT_TRUE(embedded_sct_cert
                  ->HasExtension(NID_ct_precert_scts).ValueOrDie());
  string ext_data;
  EXPECT_OK(embedded_sct_cert->OctetStringExtensionData(
      NID_ct_precert_scts, &ext_data));
  EXPECT_FALSE(ext_data.empty());

  // Don't check the print format since we're using the OpenSSL extention which
  // seems to print differently.
}

TEST_F(CtExtensionsTest, TestPoisonExtension) {
  // Sanity check
  const unique_ptr<Cert> simple_cert(Cert::FromPemString(simple_cert_));
  ASSERT_TRUE(simple_cert.get());
  EXPECT_FALSE(
      simple_cert->HasExtension(NID_ct_precert_poison).ValueOrDie());

  const unique_ptr<Cert> poison_cert(Cert::FromPemString(poison_cert_));
  ASSERT_TRUE(poison_cert.get());
  // Check we can find the extension by its advertised NID.
  // We should really be checking that the OID matches the expected OID but
  // what other extension could this cert be having that the other one doesn't?
  ASSERT_TRUE(
      poison_cert->HasExtension(NID_ct_precert_poison).ValueOrDie());

  // Now fish the extension data out using the print methods and check they
  // operate as expected.
  const StatusOr<X509_EXTENSION*> ext(
      poison_cert->GetExtension(NID_ct_precert_poison));
  ASSERT_OK(ext);

  ScopedBIO buf(BIO_new(BIO_s_mem()));
  ASSERT_NE(buf.get(), static_cast<BIO*>(NULL));

  EXPECT_EQ(1, X509V3_EXT_print(buf.get(), ext.ValueOrDie(), 0, 0));
  CHECK_EQ(1, BIO_write(buf.get(), "", 1));  // NULL-terminate
  char* result;
  BIO_get_mem_data(buf.get(), &result);

  // Should be printing "NULL".
  EXPECT_STREQ("NULL", result);
}

TEST_F(CtExtensionsTest, TestPrecertSigning) {
  // Sanity check
  const unique_ptr<Cert> simple_ca_cert(Cert::FromPemString(simple_ca_cert_));
  ASSERT_TRUE(simple_ca_cert.get());
  EXPECT_FALSE(
      simple_ca_cert
          ->HasExtendedKeyUsage(NID_ct_precert_signer)
          .ValueOrDie());

  const unique_ptr<Cert> pre_signing_cert(
      Cert::FromPemString(pre_signing_cert_));
  ASSERT_TRUE(pre_signing_cert.get());
  // Check we can find the key usage by its advertised NID.
  // We should really be checking that the OID matches the expected OID but
  // what other key usage could this cert be having that the other one doesn't?
  ASSERT_TRUE(
      pre_signing_cert
          ->HasExtendedKeyUsage(NID_ct_precert_signer)
          .ValueOrDie());
}

}  // namespace cert_trans

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  OpenSSL_add_all_algorithms();
  cert_trans::LoadCtExtensions();
  return RUN_ALL_TESTS();
}
