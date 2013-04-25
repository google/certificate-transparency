#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>

#include "log/cert.h"
#include "log/ct_extensions.h"
#include "util/testing.h"
#include "util/util.h"

namespace ct {

using std::string;

DEFINE_string(test_certs_dir, "../test/testdata", "Path to test certificates");

// TODO(ekasper): add test certs with intermediates.
// Valid certificates.
static const char kCaCert[] = "ca-cert.pem";
// Issued by ca-cert.pem
static const char kLeafCert[] = "test-cert.pem";
// Issued by ca-cert.pem
// Issued by intermediate-cert.pem
static const char kLeafWithIntermediateCert[] = "test-intermediate-cert.pem";
static const char kCaPreCert[] = "ca-pre-cert.pem";
// Issued by ca-cert.pem
static const char kPreCert[] = "test-embedded-pre-cert.pem";

static const char kInvalidCertString[] = "-----BEGIN CERTIFICATE-----\ninvalid"
    "\n-----END CERTIFICATE-----\n";

namespace {

class CertTest : public ::testing::Test {
 protected:
  string leaf_pem_;
  string ca_pem_;
  string ca_precert_pem_;
  string precert_pem_;
  string leaf_with_intermediate_pem_;

  void SetUp() {
    const string cert_dir = FLAGS_test_certs_dir;
    CHECK(util::ReadTextFile(cert_dir + "/" + kLeafCert, &leaf_pem_))
        << "Could not read test data from " << cert_dir
        << ". Wrong --test_certs_dir?";
    CHECK(util::ReadTextFile(cert_dir + "/" + kCaCert, &ca_pem_));
    CHECK(util::ReadTextFile(cert_dir + "/" + kCaPreCert, &ca_precert_pem_));
    CHECK(util::ReadTextFile(cert_dir + "/" + kPreCert, &precert_pem_));
    CHECK(util::ReadTextFile(cert_dir + "/" + kLeafWithIntermediateCert,
                             &leaf_with_intermediate_pem_));

  }
};

class TbsCertificateTest : public CertTest{};
class CertChainTest : public CertTest{};

// TODO(ekasper): test encoding methods.
TEST_F(CertTest, LoadValid) {
  Cert leaf(leaf_pem_);
  EXPECT_TRUE(leaf.IsLoaded());

  Cert ca(ca_pem_);
  EXPECT_TRUE(ca.IsLoaded());

  Cert ca_pre(ca_precert_pem_);
  EXPECT_TRUE(ca_pre.IsLoaded());

  Cert pre(precert_pem_);
  EXPECT_TRUE(pre.IsLoaded());
}

TEST_F(CertTest, LoadInvalid) {
  // Bogus certs.
  Cert invalid("");
  EXPECT_FALSE(invalid.IsLoaded());
  Cert invalid2(kInvalidCertString);
  EXPECT_FALSE(invalid2.IsLoaded());
}

TEST_F(CertTest, LoadValidFromDer) {
  Cert leaf(leaf_pem_);
  string der;
  ASSERT_EQ(Cert::TRUE, leaf.DerEncoding(&der));
  Cert second;
  EXPECT_EQ(Cert::TRUE, second.LoadFromDerString(der));
  EXPECT_TRUE(second.IsLoaded());
}

TEST_F(CertTest, LoadInvalidFromDer) {
  Cert leaf(leaf_pem_);
  // Make it look almost good for extra fun.
  string der;
  ASSERT_EQ(Cert::TRUE, leaf.DerEncoding(&der));
  Cert second;
  EXPECT_EQ(Cert::FALSE, second.LoadFromDerString(der.substr(2)));
  EXPECT_FALSE(second.IsLoaded());
}

TEST_F(CertTest, PrintSubjectName) {
  Cert leaf(leaf_pem_);
  EXPECT_EQ("C=GB, O=Certificate Transparency, ST=Wales, L=Erw Wen",
            leaf.PrintSubjectName());
}

TEST_F(CertTest, PrintIssuerName) {
  Cert leaf(leaf_pem_);
  EXPECT_EQ("C=GB, O=Certificate Transparency CA, ST=Wales, L=Erw Wen",
            leaf.PrintIssuerName());
}

TEST_F(CertTest, PrintNotBefore) {
  Cert leaf(leaf_pem_);
  EXPECT_EQ("Jun  1 00:00:00 2012 GMT", leaf.PrintNotBefore());
}

TEST_F(CertTest, PrintNotAfter) {
  Cert leaf(leaf_pem_);
  EXPECT_EQ("Jun  1 00:00:00 2022 GMT", leaf.PrintNotAfter());
}

TEST_F(CertTest, Identical) {
  Cert leaf(leaf_pem_);
  Cert ca(ca_pem_);
  EXPECT_EQ(Cert::TRUE, leaf.IsIdenticalTo(leaf));
  EXPECT_EQ(Cert::FALSE, leaf.IsIdenticalTo(ca));
  EXPECT_EQ(Cert::FALSE, ca.IsIdenticalTo(leaf));
}

TEST_F(CertTest, Extensions) {
  Cert leaf(leaf_pem_);
  Cert ca(ca_pem_);
  Cert ca_pre(ca_precert_pem_);
  Cert pre(precert_pem_);


  // Some facts we know are true about those test certs.
  EXPECT_EQ(Cert::TRUE, leaf.HasExtension(NID_authority_key_identifier));
  EXPECT_EQ(Cert::FALSE,
            leaf.HasCriticalExtension(NID_authority_key_identifier));

  EXPECT_EQ(Cert::TRUE, pre.HasCriticalExtension(ct::NID_ctPoison));

  EXPECT_EQ(Cert::FALSE, leaf.HasBasicConstraintCATrue());
  EXPECT_EQ(Cert::TRUE, ca.HasBasicConstraintCATrue());

  EXPECT_EQ(Cert::TRUE,
            ca_pre.HasExtendedKeyUsage(ct::NID_ctPrecertificateSigning));
}

TEST_F(CertTest, Issuers) {
  Cert leaf(leaf_pem_);
  Cert ca(ca_pem_);
  Cert ca_pre(ca_precert_pem_);
  Cert pre(precert_pem_);

  EXPECT_EQ(Cert::TRUE, leaf.IsIssuedBy(ca));
  EXPECT_EQ(Cert::TRUE, leaf.IsSignedBy(ca));

  EXPECT_EQ(Cert::FALSE, ca.IsIssuedBy(leaf));
  EXPECT_EQ(Cert::FALSE, ca.IsSignedBy(leaf));

  EXPECT_EQ(Cert::FALSE, leaf.IsSelfSigned());
  EXPECT_EQ(Cert::TRUE, ca.IsSelfSigned());
}

TEST_F(CertTest, DerEncodedNames) {
  Cert leaf(leaf_pem_);
  Cert ca(ca_pem_);

  ASSERT_EQ(Cert::TRUE, leaf.IsIssuedBy(ca));
 
  string leaf_subject, leaf_issuer, ca_subject, ca_issuer;
  EXPECT_EQ(Cert::TRUE, leaf.DerEncodedSubjectName(&leaf_subject));
  EXPECT_FALSE(leaf_subject.empty());

  EXPECT_EQ(Cert::TRUE, leaf.DerEncodedIssuerName(&leaf_issuer));
  EXPECT_FALSE(leaf_issuer.empty());

  EXPECT_EQ(Cert::TRUE, ca.DerEncodedSubjectName(&ca_subject));
  EXPECT_FALSE(ca_subject.empty());

  EXPECT_EQ(Cert::TRUE, ca.DerEncodedIssuerName(&ca_issuer));
  EXPECT_FALSE(ca_issuer.empty());

  EXPECT_EQ(leaf_issuer, ca_subject);
  EXPECT_EQ(ca_subject, ca_issuer);
  EXPECT_NE(leaf_subject, leaf_issuer);
}

TEST_F(TbsCertificateTest, DerEncoding) {
  Cert leaf(leaf_pem_);
  TbsCertificate tbs(leaf);

  string cert_tbs_der, raw_tbs_der;
  EXPECT_EQ(Cert::TRUE, leaf.DerEncodedTbsCertificate(&cert_tbs_der));
  EXPECT_EQ(Cert::TRUE, tbs.DerEncoding(&raw_tbs_der));
  EXPECT_EQ(cert_tbs_der, raw_tbs_der);
}

TEST_F(TbsCertificateTest, DeleteExtension) {
  Cert leaf(leaf_pem_);

  ASSERT_EQ(Cert::TRUE, leaf.HasExtension(NID_authority_key_identifier));

  TbsCertificate tbs(leaf);
  string der_before, der_after;
  EXPECT_EQ(Cert::TRUE, tbs.DerEncoding(&der_before));
  EXPECT_EQ(Cert::TRUE, tbs.DeleteExtension(NID_authority_key_identifier));
  EXPECT_EQ(Cert::TRUE, tbs.DerEncoding(&der_after));
  EXPECT_NE(der_before, der_after);

  ASSERT_EQ(Cert::FALSE, leaf.HasExtension(ct::NID_ctPoison));
  TbsCertificate tbs2(leaf);
  string der_before2, der_after2;
  EXPECT_EQ(Cert::TRUE, tbs2.DerEncoding(&der_before2));
  EXPECT_EQ(Cert::FALSE, tbs2.DeleteExtension(ct::NID_ctPoison));
  EXPECT_EQ(Cert::TRUE, tbs2.DerEncoding(&der_after2));
  EXPECT_EQ(der_before2, der_after2);
}

TEST_F(TbsCertificateTest, CopyIssuer) {
  Cert leaf(leaf_pem_);
  Cert different(leaf_with_intermediate_pem_);

  TbsCertificate tbs(leaf);
  string der_before, der_after;
  EXPECT_EQ(Cert::TRUE, tbs.DerEncoding(&der_before));
  EXPECT_EQ(Cert::TRUE, tbs.CopyIssuerFrom(different));
  EXPECT_EQ(Cert::TRUE, tbs.DerEncoding(&der_after));
  EXPECT_NE(der_before, der_after);

  TbsCertificate tbs2(leaf);
  string der_before2, der_after2;
  EXPECT_EQ(Cert::TRUE, tbs2.DerEncoding(&der_before2));
  EXPECT_EQ(Cert::TRUE, tbs2.CopyIssuerFrom(leaf));
  EXPECT_EQ(Cert::TRUE, tbs2.DerEncoding(&der_after2));
  EXPECT_EQ(der_before2, der_after2);
}


TEST_F(CertChainTest, LoadValid) {
  // A single certificate.
  CertChain chain(leaf_pem_);
  EXPECT_TRUE(chain.IsLoaded());
  EXPECT_EQ(chain.Length(), 1U);

  CertChain chain2(leaf_pem_ + ca_pem_);
  EXPECT_TRUE(chain2.IsLoaded());
  EXPECT_EQ(chain2.Length(), 2U);
}

TEST_F(CertChainTest, LoadInvalid) {
  // A single certificate.
  CertChain chain("bogus");
  EXPECT_FALSE(chain.IsLoaded());
  EXPECT_EQ(chain.Length(), 0U);

  CertChain chain2(leaf_pem_ + string(kInvalidCertString));
  EXPECT_FALSE(chain.IsLoaded());
  EXPECT_EQ(chain.Length(), 0U);
}

TEST_F(CertChainTest, AddCert) {
  CertChain chain(leaf_pem_);
  EXPECT_EQ(chain.Length(), 1U);

  chain.AddCert(new Cert(ca_pem_));
  EXPECT_EQ(chain.Length(), 2U);

  chain.AddCert(NULL);
  EXPECT_EQ(chain.Length(), 2U);

  chain.AddCert(new Cert("bogus"));
  EXPECT_EQ(chain.Length(), 2U);
}

TEST_F(CertChainTest, RemoveCert) {
  CertChain chain(leaf_pem_);
  EXPECT_EQ(chain.Length(), 1U);
  chain.RemoveCert();
  EXPECT_EQ(0U, chain.Length());

  // Does nothing.
  chain.RemoveCert();
  EXPECT_EQ(0U, chain.Length());
}

TEST_F(CertChainTest, IssuerChains) {
  // A single certificate.
  CertChain chain(leaf_pem_);
  EXPECT_EQ(Cert::TRUE, chain.IsValidCaIssuerChainMaybeLegacyRoot());
  EXPECT_EQ(Cert::TRUE, chain.IsValidSignatureChain());

  // Two certs.
  CertChain chain2(leaf_pem_ + ca_pem_);
  EXPECT_EQ(Cert::TRUE, chain.IsValidCaIssuerChainMaybeLegacyRoot());
  EXPECT_EQ(Cert::TRUE, chain.IsValidSignatureChain());

  // In reverse order.
  CertChain chain3(ca_pem_ + leaf_pem_);
  EXPECT_EQ(Cert::FALSE, chain3.IsValidCaIssuerChainMaybeLegacyRoot());
  EXPECT_EQ(Cert::FALSE, chain3.IsValidSignatureChain());

  // Invalid
  CertChain invalid("");
  EXPECT_EQ(Cert::ERROR, invalid.IsValidCaIssuerChainMaybeLegacyRoot());
  EXPECT_EQ(Cert::ERROR, invalid.IsValidSignatureChain());
}

TEST_F(CertChainTest, PreCertChain) {
  // A precert chain.
  string pem_bundle = precert_pem_ + ca_pem_;
  PreCertChain pre_chain(pem_bundle);
  ASSERT_TRUE(pre_chain.IsLoaded());
  EXPECT_EQ(pre_chain.Length(), 2U);
  EXPECT_EQ(Cert::TRUE, pre_chain.IsValidCaIssuerChainMaybeLegacyRoot());
  EXPECT_EQ(Cert::TRUE, pre_chain.IsValidSignatureChain());
  EXPECT_EQ(Cert::TRUE, pre_chain.IsWellFormed());

  // Try to construct a precert chain from regular certs.
  // The chain should load, but is not well-formed.
  pem_bundle = leaf_pem_ + ca_pem_;
  PreCertChain pre_chain2(pem_bundle);
  ASSERT_TRUE(pre_chain2.IsLoaded());
  EXPECT_EQ(pre_chain2.Length(), 2U);
  EXPECT_EQ(Cert::TRUE, pre_chain2.IsValidCaIssuerChainMaybeLegacyRoot());
  EXPECT_EQ(Cert::TRUE, pre_chain2.IsValidSignatureChain());
  EXPECT_EQ(Cert::FALSE, pre_chain2.IsWellFormed());
}

}  // namespace

}  // namespace ct

int main(int argc, char**argv) {
  ct::test::InitTesting(argv[0], &argc, &argv, true);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  ct::LoadCtExtensions();
  return RUN_ALL_TESTS();
}
