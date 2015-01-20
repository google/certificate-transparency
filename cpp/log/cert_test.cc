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

using cert_trans::Cert;
using cert_trans::CertChain;
using cert_trans::PreCertChain;
using cert_trans::TbsCertificate;
using std::string;

DEFINE_string(test_certs_dir, "../../test/testdata",
              "Path to test certificates");

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
// CA with no basic constraints and an MD2 signature.
static const char kLegacyCaCert[] = "test-no-bc-ca-cert.pem";

static const char kInvalidCertString[] =
    "-----BEGIN CERTIFICATE-----\ninvalid"
    "\n-----END CERTIFICATE-----\n";

static const char kMismatchingSigAlgsCertString[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIFWjCCBD2gAwIBAgIQGERW2P+5Xt15QiwP1NRmtTANBgkqhkiG9w0BAQsFADCB\n"
"kDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\n"
"A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxNjA0BgNV\n"
"BAMTLUNPTU9ETyBSU0EgRG9tYWluIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZlciBD\n"
"QTAeFw0xNDA1MjEwMDAwMDBaFw0xNTA1MjkyMzU5NTlaMFQxITAfBgNVBAsTGERv\n"
"bWFpbiBDb250cm9sIFZhbGlkYXRlZDEUMBIGA1UECxMLUG9zaXRpdmVTU0wxGTAX\n"
"BgNVBAMTEHZpZGVvbWFnaWNhbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n"
"ggEKAoIBAQDOMDIDA7wjsHNDp+cYa9On4oodRjnAxvgJQ852ahkZul+e816WzUTT\n"
"Bs8m0LFiXjRZtsl6AHOTVbSSK3iFrke6pVdwatVP95NsR4qQaU6ITfkD9hT01vOm\n"
"FrPv77X7RF6C0Pb8tH9ro8prpqJdTlMnjnPTQQy/ljrUaWyIQm0G1ujCApPQhQ7h\n"
"XRZYPAk0B5jSalA1q0tjjWKohlQaQMqXpHtbofvL9hUlWw6shJdd08tUH5o0UcW3\n"
"so0zHvVfwi4Gw6DiMc/a8aSmNJPO09Rf+xOYGB+wyMezH900OnuhMg6EZgMiRwfJ\n"
"O6+c6QyhLBt2Vq2Wtl8HvgwBSiCelq6FAgMBAAGjggHkMIIB4DAfBgNVHSMEGDAW\n"
"gBSQr2o6lFoL2JDqElZz30O0Oija5zAdBgNVHQ4EFgQU95g8ikB6kbC9vYcLhM38\n"
"6Qm3MyUwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYI\n"
"KwYBBQUHAwEGCCsGAQUFBwMCMFAGA1UdIARJMEcwOwYMKwYBBAGyMQECAQMEMCsw\n"
"KQYIKwYBBQUHAgEWHWh0dHBzOi8vc2VjdXJlLmNvbW9kby5uZXQvQ1BTMAgGBmeB\n"
"DAECATBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9D\n"
"T01PRE9SU0FEb21haW5WYWxpZGF0aW9uU2VjdXJlU2VydmVyQ0EuY3JsMIGFBggr\n"
"BgEFBQcBAQR5MHcwTwYIKwYBBQUHMAKGQ2h0dHA6Ly9jcnQuY29tb2RvY2EuY29t\n"
"L0NPTU9ET1JTQURvbWFpblZhbGlkYXRpb25TZWN1cmVTZXJ2ZXJDQS5jcnQwJAYI\n"
"KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTAxBgNVHREEKjAoghB2\n"
"aWRlb21hZ2ljYWwuY29tghR3d3cudmlkZW9tYWdpY2FsLmNvbTASBgkqhkiG9w0B\n"
"AQsfgeCB/FAAA4IBAQAaAf/vb3fp7PubQlrlDZbOYmCPmqvyf8LqEs0OxdS+GFOH\n"
"dn+7KoggtC/SBJRoIynklTSP2Ej8pJ+1vimqmGCKGJlA7A1kV5+BfZRnsOxwqEUC\n"
"ioN12quQp/F5ODWC6Ip/kydQd0G5ShDCddjym43LT43r8GFa4TaLifggKOS6QmK/\n"
"VJizd8y9aQEVkQQJqgdOy24i26OXFzmO15GyOxZSesd32y1nNfNH/ofIvkMrEOoF\n"
"kxYIZ0laVI3btEm3CaVnsUoEy5bZXjJpL58OI4/5HTJw/EyrAOao7t3bD2IUWsu+\n"
"qIxRCJXNjDxMb93KiEfgMzGbmmPCNkzQ6AninOSC\n"
    "-----END CERTIFICATE-----\n";

static const char kMatchingSigAlgsCertString[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIFVTCCBD2gAwIBAgIQGERW2P+5Xt15QiwP1NRmtTANBgkqhkiG9w0BAQsFADCB\n"
"kDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\n"
"A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxNjA0BgNV\n"
"BAMTLUNPTU9ETyBSU0EgRG9tYWluIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZlciBD\n"
"QTAeFw0xNDA1MjEwMDAwMDBaFw0xNTA1MjkyMzU5NTlaMFQxITAfBgNVBAsTGERv\n"
"bWFpbiBDb250cm9sIFZhbGlkYXRlZDEUMBIGA1UECxMLUG9zaXRpdmVTU0wxGTAX\n"
"BgNVBAMTEHZpZGVvbWFnaWNhbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n"
"ggEKAoIBAQDOMDIDA7wjsHNDp+cYa9On4oodRjnAxvgJQ852ahkZul+e816WzUTT\n"
"Bs8m0LFiXjRZtsl6AHOTVbSSK3iFrke6pVdwatVP95NsR4qQaU6ITfkD9hT01vOm\n"
"FrPv77X7RF6C0Pb8tH9ro8prpqJdTlMnjnPTQQy/ljrUaWyIQm0G1ujCApPQhQ7h\n"
"XRZYPAk0B5jSalA1q0tjjWKohlQaQMqXpHtbofvL9hUlWw6shJdd08tUH5o0UcW3\n"
"so0zHvVfwi4Gw6DiMc/a8aSmNJPO09Rf+xOYGB+wyMezH900OnuhMg6EZgMiRwfJ\n"
"O6+c6QyhLBt2Vq2Wtl8HvgwBSiCelq6FAgMBAAGjggHkMIIB4DAfBgNVHSMEGDAW\n"
"gBSQr2o6lFoL2JDqElZz30O0Oija5zAdBgNVHQ4EFgQU95g8ikB6kbC9vYcLhM38\n"
"6Qm3MyUwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYI\n"
"KwYBBQUHAwEGCCsGAQUFBwMCMFAGA1UdIARJMEcwOwYMKwYBBAGyMQECAQMEMCsw\n"
"KQYIKwYBBQUHAgEWHWh0dHBzOi8vc2VjdXJlLmNvbW9kby5uZXQvQ1BTMAgGBmeB\n"
"DAECATBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9D\n"
"T01PRE9SU0FEb21haW5WYWxpZGF0aW9uU2VjdXJlU2VydmVyQ0EuY3JsMIGFBggr\n"
"BgEFBQcBAQR5MHcwTwYIKwYBBQUHMAKGQ2h0dHA6Ly9jcnQuY29tb2RvY2EuY29t\n"
"L0NPTU9ET1JTQURvbWFpblZhbGlkYXRpb25TZWN1cmVTZXJ2ZXJDQS5jcnQwJAYI\n"
"KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTAxBgNVHREEKjAoghB2\n"
"aWRlb21hZ2ljYWwuY29tghR3d3cudmlkZW9tYWdpY2FsLmNvbTANBgkqhkiG9w0B\n"
"AQsFAAOCAQEAGgH/72936ez7m0Ja5Q2WzmJgj5qr8n/C6hLNDsXUvhhTh3Z/uyqI\n"
"ILQv0gSUaCMp5JU0j9hI/KSftb4pqphgihiZQOwNZFefgX2UZ7DscKhFAoqDddqr\n"
"kKfxeTg1guiKf5MnUHdBuUoQwnXY8puNy0+N6/BhWuE2i4n4ICjkukJiv1SYs3fM\n"
"vWkBFZEECaoHTstuItujlxc5jteRsjsWUnrHd9stZzXzR/6HyL5DKxDqBZMWCGdJ\n"
"WlSN27RJtwmlZ7FKBMuW2V4yaS+fDiOP+R0ycPxMqwDmqO7d2w9iFFrLvqiMUQiV\n"
"zYw8TG/dyohH4DMxm5pjwjZM0OgJ4pzkgg==\n"
"-----END CERTIFICATE-----\n";

static const char kMismatchingSigAlgsCertIssuerString[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIGCDCCA/CgAwIBAgIQKy5u6tl1NmwUim7bo3yMBzANBgkqhkiG9w0BAQwFADCB\n"
"hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\n"
"A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV\n"
"BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwMjEy\n"
"MDAwMDAwWhcNMjkwMjExMjM1OTU5WjCBkDELMAkGA1UEBhMCR0IxGzAZBgNVBAgT\n"
"EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR\n"
"Q09NT0RPIENBIExpbWl0ZWQxNjA0BgNVBAMTLUNPTU9ETyBSU0EgRG9tYWluIFZh\n"
"bGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n"
"ADCCAQoCggEBAI7CAhnhoFmk6zg1jSz9AdDTScBkxwtiBUUWOqigwAwCfx3M28Sh\n"
"bXcDow+G+eMGnD4LgYqbSRutA776S9uMIO3Vzl5ljj4Nr0zCsLdFXlIvNN5IJGS0\n"
"Qa4Al/e+Z96e0HqnU4A7fK31llVvl0cKfIWLIpeNs4TgllfQcBhglo/uLQeTnaG6\n"
"ytHNe+nEKpooIZFNb5JPJaXyejXdJtxGpdCsWTWM/06RQ1A/WZMebFEh7lgUq/51\n"
"UHg+TLAchhP6a5i84DuUHoVS3AOTJBhuyydRReZw3iVDpA3hSqXttn7IzW3uLh0n\n"
"c13cRTCAquOyQQuvvUSH2rnlG51/ruWFgqUCAwEAAaOCAWUwggFhMB8GA1UdIwQY\n"
"MBaAFLuvfgI9+qbxPISOre44mOzZMjLUMB0GA1UdDgQWBBSQr2o6lFoL2JDqElZz\n"
"30O0Oija5zAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNV\n"
"HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgG\n"
"BmeBDAECATBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNv\n"
"bS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDBxBggrBgEFBQcB\n"
"AQRlMGMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9E\n"
"T1JTQUFkZFRydXN0Q0EuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21v\n"
"ZG9jYS5jb20wDQYJKoZIhvcNAQEMBQADggIBAE4rdk+SHGI2ibp3wScF9BzWRJ2p\n"
"mj6q1WZmAT7qSeaiNbz69t2Vjpk1mA42GHWx3d1Qcnyu3HeIzg/3kCDKo2cuH1Z/\n"
"e+FE6kKVxF0NAVBGFfKBiVlsit2M8RKhjTpCipj4SzR7JzsItG8kO3KdY3RYPBps\n"
"P0/HEZrIqPW1N+8QRcZs2eBelSaz662jue5/DJpmNXMyYE7l3YphLG5SEXdoltMY\n"
"dVEVABt0iN3hxzgEQyjpFv3ZBdRdRydg1vs4O2xyopT4Qhrf7W8GjEXCBgCq5Ojc\n"
"2bXhc3js9iPc0d1sjhqPpepUfJa3w/5Vjo1JXvxku88+vZbrac2/4EjxYoIQ5QxG\n"
"V/Iz2tDIY+3GH5QFlkoakdH368+PUq4NCNk+qKBR6cGHdNXJ93SrLlP7u3r7l+L4\n"
"HyaPs9Kg4DdbKDsx5Q5XLVq4rXmsXiBmGqW5prU5wfWYQ//u+aen/e7KJD2AFsQX\n"
"j4rBYKEMrltDR5FL1ZoXX/nUh8HCjLfn4g8wGTeGrODcQgPmlKidrv0PJFGUzpII\n"
"0fxQ8ANAe4hZ7Q7drNJ3gjTcBpUC2JD5Leo31Rpg0Gcg19hCC0Wvgmje3WYkN5Ap\n"
"lBlGGSW4gNfL1IYoakRwJiNiqZ+Gb7+6kHDSVneFeO/qJakXzlByjAA6quPbYzSf\n"
"+AZxAeKCINT+b72x\n"
"-----END CERTIFICATE-----\n";

namespace {

class CertTest : public ::testing::Test {
 protected:
  string leaf_pem_;
  string ca_pem_;
  string ca_precert_pem_;
  string precert_pem_;
  string leaf_with_intermediate_pem_;
  string legacy_ca_pem_;

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
    CHECK(util::ReadTextFile(cert_dir + "/" + kLegacyCaCert, &legacy_ca_pem_));
  }
};

class TbsCertificateTest : public CertTest {};
class CertChainTest : public CertTest {};

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

TEST_F(CertTest, PrintSignatureAlgorithm) {
  Cert leaf(leaf_pem_);
  EXPECT_EQ("sha1WithRSAEncryption", leaf.PrintSignatureAlgorithm());
}

TEST_F(CertTest, TestUnsupportedAlgorithm) {
  Cert legacy(legacy_ca_pem_);
  ASSERT_EQ("md2WithRSAEncryption", legacy.PrintSignatureAlgorithm());
// MD2 is disabled by default on modern OpenSSL and you should be surprised to
// see anything else. Make the test fail if this is not the case to notify the
// user that their setup is insecure.
#ifdef OPENSSL_NO_MD2
  EXPECT_EQ(Cert::UNSUPPORTED_ALGORITHM, legacy.IsSignedBy(legacy));
#else
  LOG(WARNING) << "Skipping test: MD2 is enabled! You should configure "
               << "OpenSSL with -DOPENSSL_NO_MD2 to be safe!";
#endif
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

  EXPECT_EQ(Cert::TRUE, pre.HasCriticalExtension(cert_trans::NID_ctPoison));

  EXPECT_EQ(Cert::FALSE, leaf.HasBasicConstraintCATrue());
  EXPECT_EQ(Cert::TRUE, ca.HasBasicConstraintCATrue());

  EXPECT_EQ(Cert::TRUE, ca_pre.HasExtendedKeyUsage(
                            cert_trans::NID_ctPrecertificateSigning));
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

TEST_F(CertTest, SignatureAlgorithmMatches) {
  Cert matching_algs(kMatchingSigAlgsCertString);
  Cert issuer(kMismatchingSigAlgsCertIssuerString);
  EXPECT_EQ(Cert::TRUE, matching_algs.IsSignedBy(issuer));
  Cert mismatched_algs(kMismatchingSigAlgsCertString);
  EXPECT_EQ(Cert::FALSE, mismatched_algs.IsSignedBy(issuer));
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

  ASSERT_EQ(Cert::FALSE, leaf.HasExtension(cert_trans::NID_ctPoison));
  TbsCertificate tbs2(leaf);
  string der_before2, der_after2;
  EXPECT_EQ(Cert::TRUE, tbs2.DerEncoding(&der_before2));
  EXPECT_EQ(Cert::FALSE, tbs2.DeleteExtension(cert_trans::NID_ctPoison));
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

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  cert_trans::LoadCtExtensions();
  return RUN_ALL_TESTS();
}
