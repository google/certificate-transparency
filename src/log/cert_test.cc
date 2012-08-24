#include <gtest/gtest.h>
#include <openssl/ssl.h>
#include <string>

#include "cert.h"
#include "util.h"

static const char kCertDir[] = "../test/testdata";

// TODO: add test certs with intermediates.
// Valid certificates.
static const char kCaCert[] = "ca-cert.pem";
// Issued by ca-cert.pem
static const char kLeafCert[] = "test-cert.pem";
// Issued by ca-cert.pem
static const char kCaPreCert[] = "ca-pre-cert.pem";
// Issued by ca-pre-cert.pem
static const char kPreCert[] = "test-pre-cert.pem";

namespace {

class CertTest : public ::testing::Test {
 protected:
  std::string leaf_pem_;
  std::string ca_pem_;
  std::string ca_precert_pem_;
  std::string precert_pem_;

  void SetUp() {
    const std::string cert_dir = std::string(kCertDir);
    ASSERT_TRUE(util::ReadTextFile(cert_dir + "/" + kLeafCert, &leaf_pem_));
    ASSERT_TRUE(util::ReadTextFile(cert_dir + "/" + kCaCert, &ca_pem_));
    ASSERT_TRUE(util::ReadTextFile(cert_dir + "/" + kCaPreCert,
                                   &ca_precert_pem_));
    ASSERT_TRUE(util::ReadTextFile(cert_dir + "/" + kPreCert,
                                   &precert_pem_));
  }
};

TEST_F(CertTest, Cert) {
  Cert leaf(leaf_pem_);
  ASSERT_TRUE(leaf.IsLoaded());

  Cert ca(ca_pem_);
  ASSERT_TRUE(ca.IsLoaded());

  Cert ca_pre(ca_precert_pem_);
  ASSERT_TRUE(ca_pre.IsLoaded());

  Cert pre(precert_pem_);
  ASSERT_TRUE(pre.IsLoaded());

  // Some facts we know are true about those test certs.
  EXPECT_TRUE(leaf.HasExtension(NID_authority_key_identifier));
  EXPECT_TRUE(ca.HasExtension(NID_authority_key_identifier));

  EXPECT_TRUE(leaf.HasExtension(NID_basic_constraints));
  EXPECT_TRUE(ca.HasExtension(NID_basic_constraints));

  EXPECT_FALSE(leaf.HasBasicConstraintCA());
  EXPECT_TRUE(ca.HasBasicConstraintCA());
  EXPECT_TRUE(leaf.IsIssuedBy(ca));
  EXPECT_TRUE(leaf.IsSignedBy(ca));

  EXPECT_FALSE(ca.IsIssuedBy(leaf));
  EXPECT_FALSE(ca.IsSignedBy(leaf));

  // Some more extensions.
  EXPECT_TRUE(ca_pre.HasExtendedKeyUsage(Cert::kCtExtendedKeyUsageOID));
  EXPECT_TRUE(pre.HasExtension(Cert::kPoisonExtensionOID));
  EXPECT_TRUE(pre.IsCriticalExtension(Cert::kPoisonExtensionOID));

  // Bogus certs.
  Cert invalid("");
  EXPECT_FALSE(invalid.IsLoaded());

  Cert invalid2("-----BEGIN CERTIFICATE-----invalid-----END CERTIFICATE-----");
  EXPECT_FALSE(invalid2.IsLoaded());
}

TEST_F(CertTest, CertChain) {
  // A single certificate.
  CertChain chain(leaf_pem_);
  ASSERT_TRUE(chain.IsLoaded());

  EXPECT_EQ(chain.Length(), 1U);
  EXPECT_TRUE(chain.IsValidIssuerChain());
  EXPECT_TRUE(chain.IsValidSignatureChain());

  // Add its issuer.
  chain.AddCert(new Cert(ca_pem_));
  ASSERT_TRUE(chain.IsLoaded());
  EXPECT_EQ(chain.Length(), 2U);
  EXPECT_TRUE(chain.IsValidIssuerChain());
  EXPECT_TRUE(chain.IsValidSignatureChain());

  // In reverse order.
  CertChain chain2(ca_pem_);
  ASSERT_TRUE(chain2.IsLoaded());
  EXPECT_EQ(chain2.Length(), 1U);
  EXPECT_TRUE(chain2.IsValidIssuerChain());
  EXPECT_TRUE(chain2.IsValidSignatureChain());

  chain2.AddCert(new Cert(leaf_pem_));
  ASSERT_TRUE(chain2.IsLoaded());
  EXPECT_EQ(chain2.Length(), 2U);
  EXPECT_FALSE(chain2.IsValidIssuerChain());
  EXPECT_FALSE(chain2.IsValidSignatureChain());

  // Invalid
  CertChain invalid("");
  EXPECT_FALSE(invalid.IsLoaded());

  // A chain with three certificates. Construct from concatenated PEM entries.
  std::string pem_bundle = precert_pem_ + ca_precert_pem_ + ca_pem_;
  CertChain chain3(pem_bundle);
  ASSERT_TRUE(chain3.IsLoaded());
  EXPECT_EQ(chain3.Length(), 3U);
  EXPECT_TRUE(chain3.IsValidIssuerChain());
  EXPECT_TRUE(chain3.IsValidSignatureChain());
}

TEST_F(CertTest, PreCertChain) {
  // A precert chain.
  std::string pem_bundle = precert_pem_ + ca_precert_pem_;
  PreCertChain pre_chain(pem_bundle);
  ASSERT_TRUE(pre_chain.IsLoaded());
  EXPECT_EQ(pre_chain.Length(), 2U);
  EXPECT_EQ(pre_chain.IntermediateLength(), 0U);
  EXPECT_TRUE(pre_chain.IsValidIssuerChain());
  EXPECT_TRUE(pre_chain.IsValidSignatureChain());
  EXPECT_TRUE(pre_chain.IsWellFormed());

  // Try to construct a precert chain from regular certs.
  // The chain should load, but is not well-formed.
  pem_bundle = leaf_pem_ + ca_pem_;
  PreCertChain pre_chain2(pem_bundle);
  ASSERT_TRUE(pre_chain2.IsLoaded());
  EXPECT_EQ(pre_chain2.Length(), 2U);
  EXPECT_EQ(pre_chain2.IntermediateLength(), 0U);
  EXPECT_TRUE(pre_chain2.IsValidIssuerChain());
  EXPECT_TRUE(pre_chain2.IsValidSignatureChain());
  EXPECT_FALSE(pre_chain2.IsWellFormed());
}

}  // namespace

int main(int argc, char**argv) {
  ::testing::InitGoogleTest(&argc, argv);
  SSL_library_init();
  return RUN_ALL_TESTS();
}
