/* -*- indent-tabs-mode: nil -*- */
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <memory>
#include <string>

#include "log/cert.h"
#include "log/cert_checker.h"
#include "log/ct_extensions.h"
#include "util/status_test_util.h"
#include "util/testing.h"
#include "util/util.h"

using cert_trans::Cert;
using cert_trans::CertChain;
using cert_trans::CertChecker;
using cert_trans::PreCertChain;
using std::move;
using std::string;
using std::unique_ptr;
using std::vector;
using util::testing::StatusIs;

// Valid certificates.
// Self-signed
static const char kCaCert[] = "ca-cert.pem";
// Issued by ca-cert.pem
static const char kLeafCert[] = "test-cert.pem";
// Issued by ca-cert.pem
static const char kCaPreCert[] = "ca-pre-cert.pem";
// Issued by ca-cert.pem
static const char kPreCert[] = "test-embedded-pre-cert.pem";
// Issued by ca-pre-cert.pem
static const char kPreWithPreCaCert[] =
    "test-embedded-with-preca-pre-cert.pem";
// Issued by ca-cert.pem
static const char kIntermediateCert[] = "intermediate-cert.pem";
// Issued by intermediate-cert.pem
static const char kChainLeafCert[] = "test-intermediate-cert.pem";
// CA with no basic constraints.
static const char kCaNoBCCert[] = "test-no-bc-ca-cert.pem";
// Chain terminating in that CA.
static const char kNoBCChain[] = "test-no-bc-cert-chain.pem";
// Chain where a leaf cert issues another cert
static const char kBadNoBCChain[] = "test-no-ca-cert-chain.pem";
// Chain that has two matching issuers.
static const char kCollisionChain[] = "test-issuer-collision-chain.pem";
// Two CA certs that have identical name and no AKI.
static const char kCollisionRoot1[] = "test-colliding-root1.pem";
static const char kCollisionRoot2[] = "test-colliding-root2.pem";
static const char kCollidingRoots[] = "test-colliding-roots.pem";
// A chain terminating with an MD2 intermediate.
// Issuer is test-no-bc-ca-cert.pem.
static const char kMd2Chain[] = "test-md2-chain.pem";
// A file which doesn't exist.
static const char kNonexistent[] = "test-nonexistent.pem";
// A file with corrupted contents (bit flip from ca-cert.pem).
static const char kCorrupted[] = "test-corrupted.pem";

// Corresponds to kCaCert.
static const char kCaCertPem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk\n"
    "MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX\n"
    "YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw\n"
    "MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu\n"
    "c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf\n"
    "MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7\n"
    "jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP\n"
    "KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL\n"
    "svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk\n"
    "tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG\n"
    "A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO\n"
    "MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB\n"
    "/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt\n"
    "OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy\n"
    "f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP\n"
    "OwqULg==\n"
    "-----END CERTIFICATE-----\n";
// Corresponds to kIntermediateCert.
static const char kIntermediateCertPem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC3TCCAkagAwIBAgIBCTANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk\n"
    "MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX\n"
    "YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw\n"
    "MDAwMDBaMGIxCzAJBgNVBAYTAkdCMTEwLwYDVQQKEyhDZXJ0aWZpY2F0ZSBUcmFu\n"
    "c3BhcmVuY3kgSW50ZXJtZWRpYXRlIENBMQ4wDAYDVQQIEwVXYWxlczEQMA4GA1UE\n"
    "BxMHRXJ3IFdlbjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA12pnjRFvUi5V\n"
    "/4IckGQlCLcHSxTXcRWQZPeSfv3tuHE1oTZe594Yy9XOhl+GDHj0M7TQ09NAdwLn\n"
    "o+9UKx3+m7qnzflNxZdfxyn4bxBfOBskNTXPnIAPXKeAwdPIRADuZdFu6c9S24rf\n"
    "/lD1xJM1CyGQv1DVvDbzysWo2q6SzYsCAwEAAaOBrzCBrDAdBgNVHQ4EFgQUllUI\n"
    "BQJ4R56Hc3ZBMbwUOkfiKaswfQYDVR0jBHYwdIAUX52IDchz5lTU+A3Y5rDBJLRH\n"
    "w1WhWaRXMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu\n"
    "c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuggEA\n"
    "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAIgbascZrcdzglcP2qi73\n"
    "LPd2G+er1/w5wxpM/hvZbWc0yoLyLd5aDIu73YJde28+dhKtjbMAp+IRaYhgIyYi\n"
    "hMOqXSGR79oQv5I103s6KjQNWUGblKSFZvP6w82LU9Wk6YJw6tKXsHIQ+c5KITix\n"
    "iBEUO5P6TnqH3TfhOF8sKQg=\n"
    "-----END CERTIFICATE-----\n";

static const char kDsaPrecertChain[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIGbzCCBhWgAwIBAgIQQyzKVQswSJU51uhTRKJOcjALBglghkgBZQMEAwIwQDEL\n"
"MAkGA1UEBhMCVVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjEaMBgGA1UEAxMRdGhh\n"
"d3RlIERTQSBTU0wgQ0EwHhcNMTUxMjI5MDAwMDAwWhcNMTcxMjI3MjM1OTU5WjCB\n"
"pzETMBEGCysGAQQBgjc8AgEDEwJHRTEdMBsGA1UEDxMUUHJpdmF0ZSBPcmdhbml6\n"
"YXRpb24xEzARBgNVBAoUClVuaVBBWSBMVEQxEjAQBgNVBAUTCTQwMTk1Mzk5OTEL\n"
"MAkGA1UEBhMCR0UxEDAOBgNVBAgTB1RiaWxpc2kxEDAOBgNVBAcUB1RiaWxpc2kx\n"
"FzAVBgNVBAMUDnd3dy51bmlwYXkuY29tMIIDRzCCAjoGByqGSM44BAEwggItAoIB\n"
"AQClyTxv5WDYR4Dv2+pCaEEFTtEayHGtbMmaHG3RR24DVgxtlS//xmk6z4fO03uj\n"
"EdxylJ7UDZp1GrYxJXts2bixxH2jsoiuzs/PiCyS1TGsrdkD5Vi/y3wkYRzM3iBt\n"
"abKu23ZANP6WansDX4jILYxOs2cc4GEQepOsuHqn2LWCBvxGP3KmTo0YwuV+sSO8\n"
"IFTvHsGb0ZFKzZdFfjqPxXbGXiCGHHhuispi23SKqHEXdRjlyuWRjCDHJsyefKTk\n"
"HW+1nx7lSZIBBB6tPXxdtk/cNcJESoZmXl9aNsYdo/63mQI5aA6iUXX09/FNTIMh\n"
"dp3aoQHePhdGRRTOxoADIrVNAiEA45OTlEY+5SayLLZyqvLduEKEzOntK0ssMIUp\n"
"GIXGMo8CggEBAJlGxvWVGST03IYlimBHX4VNpkuKqXGyMSnjNP0niqxVYmEjDUeN\n"
"cqyoBoBEJO1wsT2/v4IUQXQoQ5yW95D/sfXEF806MLqkgzOPNhXHZsyjqntHMAKj\n"
"t4hi9XOfjHUKXDINGpk0AwAk1Aajj4DavWjZ/8gBZWgkNHjNnV9UuBnIeBJmOO7C\n"
"s57cQ98p3TpGHgk0l8+r3ELnaLf/UhJRr6C7SGIEdddMXGbnR1w968IRVZygL7lx\n"
"3UF9XJFGcR6TuKt5/PA8oxqU+Phl+EEJm7TJ/+pT5KLEo+o0DghM4GVKC6h9u/gg\n"
"4gBdsEQ4OtkLZ1pSU+Nvyz22TVWTz3D35XoDggEFAAKCAQA//na/RFHzfeuYBoaY\n"
"0v4SkKwNwAInGn7pAvaF8AiENwesVnVTu8l7z+hi1CYv4fEGJNKkf44j6TTwjds8\n"
"QTjJbGrg5RzXp3LGrJbAzW8zW/CxabF0pMo4eod3NjTC4sSgVTMawpw2oag/1T79\n"
"LmDeGEJPbajmUUee9tfJJQK/UirzcB1n9/O2GK0Uthu8rH77IQPcM5Y8ambgwbIG\n"
"eFXMSU1AODKj83kqPJmRvDcAIQs5ShA+yghs6qfA1m9V4At2sQtgf7iVkD6HKH9X\n"
"v8izGABvDBVlk3ZRW2WXMeTyGeCl1T43+mnXMGs9i4r1KDuFdt/0WbXVA+F7AVYy\n"
"u/cGo4IBljCCAZIwJQYDVR0RBB4wHIIKdW5pcGF5LmNvbYIOd3d3LnVuaXBheS5j\n"
"b20wCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwKwYDVR0fBCQwIjAgoB6gHIYa\n"
"aHR0cDovL3RlLnN5bWNiLmNvbS90ZS5jcmwwcwYDVR0gBGwwajBoBgtghkgBhvhF\n"
"AQcwATBZMCYGCCsGAQUFBwIBFhpodHRwczovL3d3dy50aGF3dGUuY29tL2NwczAv\n"
"BggrBgEFBQcCAjAjDCFodHRwczovL3d3dy50aGF3dGUuY29tL3JlcG9zaXRvcnkw\n"
"HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFMoTsU3s\n"
"mn62fEUeuB3k0shyGrEdMFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYTaHR0\n"
"cDovL3RlLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0cDovL3RlLnN5bWNiLmNv\n"
"bS90ZS5jcnQwEwYKKwYBBAHWeQIEAwEB/wQCBQAwCwYJYIZIAWUDBAMCA0cAMEQC\n"
"IGqj1ElLQljLIir0ZWTzmr0wOXG2B8X649SNqOHhzXikAiAE9qn9RiIe/fpphfnx\n"
"jks8c0MAUgqmpKIZWTpvNhja6Q==\n"
"-----END CERTIFICATE-----\n"
"-----BEGIN CERTIFICATE-----\n"
"MIIGJDCCBcmgAwIBAgIQbT3s+pt4qr0oAI3ZcDdjDjALBglghkgBZQMEAwIwga4x\n"
"CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwx0aGF3dGUsIEluYy4xKDAmBgNVBAsTH0Nl\n"
"cnRpZmljYXRpb24gU2VydmljZXMgRGl2aXNpb24xODA2BgNVBAsTLyhjKSAyMDEy\n"
"IHRoYXd0ZSwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MSQwIgYDVQQD\n"
"Ext0aGF3dGUgUHJpbWFyeSBSb290IENBIC0gRzQwHhcNMTIxMjIwMDAwMDAwWhcN\n"
"MjIxMjE5MjM1OTU5WjBAMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMdGhhd3RlLCBJ\n"
"bmMuMRowGAYDVQQDExF0aGF3dGUgRFNBIFNTTCBDQTCCA0gwggI6BgcqhkjOOAQB\n"
"MIICLQKCAQEAsOkfT0p9OXj0/j9H+m2Ejyu6VTLpjydK1/dWyl/AQS5WE5GPgy0i\n"
"6oJQCSEKLcZtJCcnrx9X2WJq/U9sxSydq0oP1R7BqXiRs3fphkJnBhW/OGJNnw13\n"
"dnBrt9ffmaZNFFRCUQOsGDsSjBPOUQ4tuenBeF3Zs+DAfkDXzxcrK4OQs6qTYubn\n"
"8QUphcoMaUURJv9aY8VfVpODN3Z5FeamrY72zAcGvc9ajFl45vVlK/dDbu8kMMdp\n"
"b1wuNMTWUo/dxdPrtgpJA3ZnN9MDSzs2tcGWxYnpWFZTndTePn7xU0b3r/pN/ys7\n"
"i5FBr1yqYVWelt5uGLMg+ZQ22GQnga8/eQIhAKdVID3cRKJNm0Rd77SM/GgY430w\n"
"mefDvxS6pQDGnAzXAoIBAQCLQiKLU8kRBsWIkeuRPKlbqwSMkbNwaOYK6/Lh8x5k\n"
"20djAqPOurHtzNWnAPAvZPYSjL+PR1ydHq4tRDEgjaVYlb5ZZeD8L6v0J/OWNTpS\n"
"SmeKzHfD1QRP/2dxqiNweivUR4vw7m6wg8Y5ZxOFKbgAfdM08z2hbjkucrCzkbCr\n"
"0NQUkUy+N4gvMKOIVDYVUiKUFSJmlRiYlCXJNaoIkKWcb4NjRBHjDKbmm4+Isco4\n"
"PUQ3E7V+CdS6C8hOPdDwhcYm6FPrgbTPcuuoJgEI6YXjgywGCMja6zwEmU1F9NH6\n"
"9TmpZiKCFDVhrBd5KgOemiiveAE2AAU1ctYz1pkqt2dXA4IBBgACggEBAJzaudYH\n"
"djJGC5gPXFS+oWZc4SEicF5teHo2ZkI86j8TDGZWBCXHng3m/JrY3qT11tBU4go/\n"
"XR5AQ9GYtLAiOXZKIdFSjyjrDGVotWNxpoZi1hXpVEsCAEwyWqKdO+47zUF2/tgc\n"
"QzAnAwbb2NV9D35rg3wKenUKdQfp98PrlWUh2UOmFkae83eLr/7VxEF4nOF+CI/4\n"
"Kx9y6Qy3So/OHucSp8206yqJ80EyYox9cnAeS81xBwJqn1LIPRFGJ85cEXRldATI\n"
"+CvgvfdnpWnJaPPUvJoaPF9DVfi4FTGV7aFfeQfi9QemF8WMPq0JpdrFkfrnGVw9\n"
"wxGzySeiXj7UDhKjggFCMIIBPjASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB\n"
"/wQEAwIBBjAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3Nw\n"
"LnRoYXd0ZS5jb20wOwYDVR0gBDQwMjAwBgRVHSAAMCgwJgYIKwYBBQUHAgEWGmh0\n"
"dHBzOi8vd3d3LnRoYXd0ZS5jb20vY3BzMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6\n"
"Ly9jcmwudGhhd3RlLmNvbS9UaGF3dGVQQ0EtRzQuY3JsMC4GA1UdEQQnMCWkIzAh\n"
"MR8wHQYDVQQDExZTWU1DLURTQS1DQS0yMDQ4LTI1Ni00MB0GA1UdDgQWBBTKE7FN\n"
"7Jp+tnxFHrgd5NLIchqxHTAfBgNVHSMEGDAWgBTHZ4lkIvGdsfOLg6bCDpmTUXbr\n"
"ljALBglghkgBZQMEAwIDSAAwRQIhAKb8sDyC2UehqUcEPUQ65bnmmtiplEplDUZt\n"
"ULqZQweDAiAr4MAcnfC9otwLcBllGVA4vsOKPsFSq5u2EPn3ovIynw==\n"
"-----END CERTIFICATE-----\n";

// This was generated from the above by manually flipping a bit
// in one of the signature bytes of the precert.
static const char kDsaPrecertChainInvalidSig[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIGbzCCBhWgAwIBAgIQQyzKVQswSJU51uhTRKJOcjALBglghkgBZQMEAwIwQDEL\n"
"MAkGA1UEBhMCVVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjEaMBgGA1UEAxMRdGhh\n"
"d3RlIERTQSBTU0wgQ0EwHhcNMTUxMjI5MDAwMDAwWhcNMTcxMjI3MjM1OTU5WjCB\n"
"pzETMBEGCysGAQQBgjc8AgEDEwJHRTEdMBsGA1UEDxMUUHJpdmF0ZSBPcmdhbml6\n"
"YXRpb24xEzARBgNVBAoUClVuaVBBWSBMVEQxEjAQBgNVBAUTCTQwMTk1Mzk5OTEL\n"
"MAkGA1UEBhMCR0UxEDAOBgNVBAgTB1RiaWxpc2kxEDAOBgNVBAcUB1RiaWxpc2kx\n"
"FzAVBgNVBAMUDnd3dy51bmlwYXkuY29tMIIDRzCCAjoGByqGSM44BAEwggItAoIB\n"
"AQClyTxv5WDYR4Dv2+pCaEEFTtEayHGtbMmaHG3RR24DVgxtlS//xmk6z4fO03uj\n"
"EdxylJ7UDZp1GrYxJXts2bixxH2jsoiuzs/PiCyS1TGsrdkD5Vi/y3wkYRzM3iBt\n"
"abKu23ZANP6WansDX4jILYxOs2cc4GEQepOsuHqn2LWCBvxGP3KmTo0YwuV+sSO8\n"
"IFTvHsGb0ZFKzZdFfjqPxXbGXiCGHHhuispi23SKqHEXdRjlyuWRjCDHJsyefKTk\n"
"HW+1nx7lSZIBBB6tPXxdtk/cNcJESoZmXl9aNsYdo/63mQI5aA6iUXX09/FNTIMh\n"
"dp3aoQHePhdGRRTOxoADIrVNAiEA45OTlEY+5SayLLZyqvLduEKEzOntK0ssMIUp\n"
"GIXGMo8CggEBAJlGxvWVGST03IYlimBHX4VNpkuKqXGyMSnjNP0niqxVYmEjDUeN\n"
"cqyoBoBEJO1wsT2/v4IUQXQoQ5yW95D/sfXEF806MLqkgzOPNhXHZsyjqntHMAKj\n"
"t4hi9XOfjHUKXDINGpk0AwAk1Aajj4DavWjZ/8gBZWgkNHjNnV9UuBnIeBJmOO7C\n"
"s57cQ98p3TpGHgk0l8+r3ELnaLf/UhJRr6C7SGIEdddMXGbnR1w968IRVZygL7lx\n"
"3UF9XJFGcR6TuKt5/PA8oxqU+Phl+EEJm7TJ/+pT5KLEo+o0DghM4GVKC6h9u/gg\n"
"4gBdsEQ4OtkLZ1pSU+Nvyz22TVWTz3D35XoDggEFAAKCAQA//na/RFHzfeuYBoaY\n"
"0v4SkKwNwAInGn7pAvaF8AiENwesVnVTu8l7z+hi1CYv4fEGJNKkf44j6TTwjds8\n"
"QTjJbGrg5RzXp3LGrJbAzW8zW/CxabF0pMo4eod3NjTC4sSgVTMawpw2oag/1T79\n"
"LmDeGEJPbajmUUee9tfJJQK/UirzcB1n9/O2GK0Uthu8rH77IQPcM5Y8ambgwbIG\n"
"eFXMSU1AODKj83kqPJmRvDcAIQs5ShA+yghs6qfA1m9V4At2sQtgf7iVkD6HKH9X\n"
"v8izGABvDBVlk3ZRW2WXMeTyGeCl1T43+mnXMGs9i4r1KDuFdt/0WbXVA+F7AVYy\n"
"u/cGo4IBljCCAZIwJQYDVR0RBB4wHIIKdW5pcGF5LmNvbYIOd3d3LnVuaXBheS5j\n"
"b20wCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwKwYDVR0fBCQwIjAgoB6gHIYa\n"
"aHR0cDovL3RlLnN5bWNiLmNvbS90ZS5jcmwwcwYDVR0gBGwwajBoBgtghkgBhvhF\n"
"AQcwATBZMCYGCCsGAQUFBwIBFhpodHRwczovL3d3dy50aGF3dGUuY29tL2NwczAv\n"
"BggrBgEFBQcCAjAjDCFodHRwczovL3d3dy50aGF3dGUuY29tL3JlcG9zaXRvcnkw\n"
"HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFMoTsU3s\n"
"mn62fEUeuB3k0shyGrEdMFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYTaHR0\n"
"cDovL3RlLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0cDovL3RlLnN5bWNiLmNv\n"
"bS90ZS5jcnQwEwYKKwYBBAHWeQIEAwEB/wQCBQAwCwYJYIZIAWUDBAMCA0cAMEQC\n"
"IGqj1ElLQljLIir0ZWTzmr0wOXG2B8X649SNqOHhzXikAiAE9qr9RiIe/fpphfnx\n"
"jks8c0MAUgqmpKIZWTpvNhja6Q==\n"
"-----END CERTIFICATE-----\n"
"-----BEGIN CERTIFICATE-----\n"
"MIIGJDCCBcmgAwIBAgIQbT3s+pt4qr0oAI3ZcDdjDjALBglghkgBZQMEAwIwga4x\n"
"CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwx0aGF3dGUsIEluYy4xKDAmBgNVBAsTH0Nl\n"
"cnRpZmljYXRpb24gU2VydmljZXMgRGl2aXNpb24xODA2BgNVBAsTLyhjKSAyMDEy\n"
"IHRoYXd0ZSwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MSQwIgYDVQQD\n"
"Ext0aGF3dGUgUHJpbWFyeSBSb290IENBIC0gRzQwHhcNMTIxMjIwMDAwMDAwWhcN\n"
"MjIxMjE5MjM1OTU5WjBAMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMdGhhd3RlLCBJ\n"
"bmMuMRowGAYDVQQDExF0aGF3dGUgRFNBIFNTTCBDQTCCA0gwggI6BgcqhkjOOAQB\n"
"MIICLQKCAQEAsOkfT0p9OXj0/j9H+m2Ejyu6VTLpjydK1/dWyl/AQS5WE5GPgy0i\n"
"6oJQCSEKLcZtJCcnrx9X2WJq/U9sxSydq0oP1R7BqXiRs3fphkJnBhW/OGJNnw13\n"
"dnBrt9ffmaZNFFRCUQOsGDsSjBPOUQ4tuenBeF3Zs+DAfkDXzxcrK4OQs6qTYubn\n"
"8QUphcoMaUURJv9aY8VfVpODN3Z5FeamrY72zAcGvc9ajFl45vVlK/dDbu8kMMdp\n"
"b1wuNMTWUo/dxdPrtgpJA3ZnN9MDSzs2tcGWxYnpWFZTndTePn7xU0b3r/pN/ys7\n"
"i5FBr1yqYVWelt5uGLMg+ZQ22GQnga8/eQIhAKdVID3cRKJNm0Rd77SM/GgY430w\n"
"mefDvxS6pQDGnAzXAoIBAQCLQiKLU8kRBsWIkeuRPKlbqwSMkbNwaOYK6/Lh8x5k\n"
"20djAqPOurHtzNWnAPAvZPYSjL+PR1ydHq4tRDEgjaVYlb5ZZeD8L6v0J/OWNTpS\n"
"SmeKzHfD1QRP/2dxqiNweivUR4vw7m6wg8Y5ZxOFKbgAfdM08z2hbjkucrCzkbCr\n"
"0NQUkUy+N4gvMKOIVDYVUiKUFSJmlRiYlCXJNaoIkKWcb4NjRBHjDKbmm4+Isco4\n"
"PUQ3E7V+CdS6C8hOPdDwhcYm6FPrgbTPcuuoJgEI6YXjgywGCMja6zwEmU1F9NH6\n"
"9TmpZiKCFDVhrBd5KgOemiiveAE2AAU1ctYz1pkqt2dXA4IBBgACggEBAJzaudYH\n"
"djJGC5gPXFS+oWZc4SEicF5teHo2ZkI86j8TDGZWBCXHng3m/JrY3qT11tBU4go/\n"
"XR5AQ9GYtLAiOXZKIdFSjyjrDGVotWNxpoZi1hXpVEsCAEwyWqKdO+47zUF2/tgc\n"
"QzAnAwbb2NV9D35rg3wKenUKdQfp98PrlWUh2UOmFkae83eLr/7VxEF4nOF+CI/4\n"
"Kx9y6Qy3So/OHucSp8206yqJ80EyYox9cnAeS81xBwJqn1LIPRFGJ85cEXRldATI\n"
"+CvgvfdnpWnJaPPUvJoaPF9DVfi4FTGV7aFfeQfi9QemF8WMPq0JpdrFkfrnGVw9\n"
"wxGzySeiXj7UDhKjggFCMIIBPjASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB\n"
"/wQEAwIBBjAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3Nw\n"
"LnRoYXd0ZS5jb20wOwYDVR0gBDQwMjAwBgRVHSAAMCgwJgYIKwYBBQUHAgEWGmh0\n"
"dHBzOi8vd3d3LnRoYXd0ZS5jb20vY3BzMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6\n"
"Ly9jcmwudGhhd3RlLmNvbS9UaGF3dGVQQ0EtRzQuY3JsMC4GA1UdEQQnMCWkIzAh\n"
"MR8wHQYDVQQDExZTWU1DLURTQS1DQS0yMDQ4LTI1Ni00MB0GA1UdDgQWBBTKE7FN\n"
"7Jp+tnxFHrgd5NLIchqxHTAfBgNVHSMEGDAWgBTHZ4lkIvGdsfOLg6bCDpmTUXbr\n"
"ljALBglghkgBZQMEAwIDSAAwRQIhAKb8sDyC2UehqUcEPUQ65bnmmtiplEplDUZt\n"
"ULqZQweDAiAr4MAcnfC9otwLcBllGVA4vsOKPsFSq5u2EPn3ovIynw==\n"
"-----END CERTIFICATE-----\n";

static const char kDsaPrecertChainRootOnly[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIGJDCCBcmgAwIBAgIQbT3s+pt4qr0oAI3ZcDdjDjALBglghkgBZQMEAwIwga4x\n"
"CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwx0aGF3dGUsIEluYy4xKDAmBgNVBAsTH0Nl\n"
"cnRpZmljYXRpb24gU2VydmljZXMgRGl2aXNpb24xODA2BgNVBAsTLyhjKSAyMDEy\n"
"IHRoYXd0ZSwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MSQwIgYDVQQD\n"
"Ext0aGF3dGUgUHJpbWFyeSBSb290IENBIC0gRzQwHhcNMTIxMjIwMDAwMDAwWhcN\n"
"MjIxMjE5MjM1OTU5WjBAMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMdGhhd3RlLCBJ\n"
"bmMuMRowGAYDVQQDExF0aGF3dGUgRFNBIFNTTCBDQTCCA0gwggI6BgcqhkjOOAQB\n"
"MIICLQKCAQEAsOkfT0p9OXj0/j9H+m2Ejyu6VTLpjydK1/dWyl/AQS5WE5GPgy0i\n"
"6oJQCSEKLcZtJCcnrx9X2WJq/U9sxSydq0oP1R7BqXiRs3fphkJnBhW/OGJNnw13\n"
"dnBrt9ffmaZNFFRCUQOsGDsSjBPOUQ4tuenBeF3Zs+DAfkDXzxcrK4OQs6qTYubn\n"
"8QUphcoMaUURJv9aY8VfVpODN3Z5FeamrY72zAcGvc9ajFl45vVlK/dDbu8kMMdp\n"
"b1wuNMTWUo/dxdPrtgpJA3ZnN9MDSzs2tcGWxYnpWFZTndTePn7xU0b3r/pN/ys7\n"
"i5FBr1yqYVWelt5uGLMg+ZQ22GQnga8/eQIhAKdVID3cRKJNm0Rd77SM/GgY430w\n"
"mefDvxS6pQDGnAzXAoIBAQCLQiKLU8kRBsWIkeuRPKlbqwSMkbNwaOYK6/Lh8x5k\n"
"20djAqPOurHtzNWnAPAvZPYSjL+PR1ydHq4tRDEgjaVYlb5ZZeD8L6v0J/OWNTpS\n"
"SmeKzHfD1QRP/2dxqiNweivUR4vw7m6wg8Y5ZxOFKbgAfdM08z2hbjkucrCzkbCr\n"
"0NQUkUy+N4gvMKOIVDYVUiKUFSJmlRiYlCXJNaoIkKWcb4NjRBHjDKbmm4+Isco4\n"
"PUQ3E7V+CdS6C8hOPdDwhcYm6FPrgbTPcuuoJgEI6YXjgywGCMja6zwEmU1F9NH6\n"
"9TmpZiKCFDVhrBd5KgOemiiveAE2AAU1ctYz1pkqt2dXA4IBBgACggEBAJzaudYH\n"
"djJGC5gPXFS+oWZc4SEicF5teHo2ZkI86j8TDGZWBCXHng3m/JrY3qT11tBU4go/\n"
"XR5AQ9GYtLAiOXZKIdFSjyjrDGVotWNxpoZi1hXpVEsCAEwyWqKdO+47zUF2/tgc\n"
"QzAnAwbb2NV9D35rg3wKenUKdQfp98PrlWUh2UOmFkae83eLr/7VxEF4nOF+CI/4\n"
"Kx9y6Qy3So/OHucSp8206yqJ80EyYox9cnAeS81xBwJqn1LIPRFGJ85cEXRldATI\n"
"+CvgvfdnpWnJaPPUvJoaPF9DVfi4FTGV7aFfeQfi9QemF8WMPq0JpdrFkfrnGVw9\n"
"wxGzySeiXj7UDhKjggFCMIIBPjASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB\n"
"/wQEAwIBBjAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3Nw\n"
"LnRoYXd0ZS5jb20wOwYDVR0gBDQwMjAwBgRVHSAAMCgwJgYIKwYBBQUHAgEWGmh0\n"
"dHBzOi8vd3d3LnRoYXd0ZS5jb20vY3BzMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6\n"
"Ly9jcmwudGhhd3RlLmNvbS9UaGF3dGVQQ0EtRzQuY3JsMC4GA1UdEQQnMCWkIzAh\n"
"MR8wHQYDVQQDExZTWU1DLURTQS1DQS0yMDQ4LTI1Ni00MB0GA1UdDgQWBBTKE7FN\n"
"7Jp+tnxFHrgd5NLIchqxHTAfBgNVHSMEGDAWgBTHZ4lkIvGdsfOLg6bCDpmTUXbr\n"
"ljALBglghkgBZQMEAwIDSAAwRQIhAKb8sDyC2UehqUcEPUQ65bnmmtiplEplDUZt\n"
"ULqZQweDAiAr4MAcnfC9otwLcBllGVA4vsOKPsFSq5u2EPn3ovIynw==\n"
"-----END CERTIFICATE-----\n";

namespace {

class CertCheckerTest : public ::testing::Test {
 protected:
  CertCheckerTest()
      : cert_dir_(FLAGS_test_srcdir + "/test/testdata"),
        cert_dir_v2_(FLAGS_test_srcdir + "/test/testdata/v2/") {
  }

  string leaf_pem_;
  string ca_precert_pem_;
  string precert_pem_;
  string precert_with_preca_pem_;
  string intermediate_pem_;
  string chain_leaf_pem_;
  string ca_pem_;
  CertChecker checker_;
  const string cert_dir_;
  const string cert_dir_v2_;

  void SetUp() {
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kLeafCert, &leaf_pem_))
        << "Could not read test data from " << cert_dir_
        << ". Wrong --test_srcdir?";
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kCaPreCert, &ca_precert_pem_));
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kPreCert, &precert_pem_));
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kPreWithPreCaCert,
                             &precert_with_preca_pem_));
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kIntermediateCert,
                             &intermediate_pem_));
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kChainLeafCert,
                             &chain_leaf_pem_));
    CHECK(util::ReadTextFile(cert_dir_ + "/" + kCaCert, &ca_pem_));
  }
};

TEST_F(CertCheckerTest, LoadTrustedCertificates) {
  EXPECT_EQ(0U, checker_.NumTrustedCertificates());

  EXPECT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert));
  EXPECT_EQ(1U, checker_.NumTrustedCertificates());

  EXPECT_TRUE(
      checker_.LoadTrustedCertificates(cert_dir_ + "/" + kIntermediateCert));
  EXPECT_EQ(2U, checker_.NumTrustedCertificates());
}

TEST_F(CertCheckerTest, LoadTrustedCertificatesFromMemory) {
  vector<string> certs;
  certs.push_back(string(kCaCertPem));

  EXPECT_TRUE(checker_.LoadTrustedCertificates(certs));
  EXPECT_EQ(1U, checker_.NumTrustedCertificates());
}

TEST_F(CertCheckerTest, LoadTrustedCertificatesLoadsAll) {
  EXPECT_EQ(0U, checker_.NumTrustedCertificates());

  EXPECT_TRUE(
      checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCollidingRoots));
  EXPECT_EQ(2U, checker_.NumTrustedCertificates());
}

TEST_F(CertCheckerTest, LoadTrustedCertificatesFromMemoryLoadsAll) {
  vector<string> certs;
  certs.push_back(string(kCaCertPem));
  certs.push_back(string(kIntermediateCertPem));

  EXPECT_TRUE(checker_.LoadTrustedCertificates(certs));
  EXPECT_EQ(2U, checker_.NumTrustedCertificates());
}

TEST_F(CertCheckerTest, LoadTrustedCertificatesIgnoresDuplicates) {
  EXPECT_EQ(0U, checker_.NumTrustedCertificates());

  EXPECT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert));
  EXPECT_EQ(1U, checker_.NumTrustedCertificates());
  EXPECT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert));
  EXPECT_EQ(1U, checker_.NumTrustedCertificates());
}

TEST_F(CertCheckerTest, LoadTrustedCertificatesMissingFile) {
  EXPECT_EQ(0U, checker_.NumTrustedCertificates());

  EXPECT_FALSE(
      checker_.LoadTrustedCertificates(cert_dir_ + "/" + kNonexistent));
  EXPECT_EQ(0U, checker_.NumTrustedCertificates());
}

TEST_F(CertCheckerTest, LoadTrustedCertificatesCorruptedFile) {
  EXPECT_EQ(0U, checker_.NumTrustedCertificates());

  EXPECT_FALSE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCorrupted));
  EXPECT_EQ(0U, checker_.NumTrustedCertificates());
}

TEST_F(CertCheckerTest, Certificate) {
  CertChain chain(leaf_pem_);
  ASSERT_TRUE(chain.IsLoaded());

  // Fail as we have no CA certs.
  EXPECT_THAT(checker_.CheckCertChain(&chain),
              StatusIs(util::error::FAILED_PRECONDITION));

  // Load CA certs and expect success.
  EXPECT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert));
  EXPECT_OK(checker_.CheckCertChain(&chain));
  EXPECT_EQ(2U, chain.Length());
}

TEST_F(CertCheckerTest, CertificateWithRoot) {
  CertChain chain(leaf_pem_);
  ASSERT_TRUE(chain.IsLoaded());
  ASSERT_TRUE(chain.AddCert(Cert::FromPemString(ca_pem_)));

  // Fail as even though we give a CA cert, it's not in the local store.
  EXPECT_THAT(checker_.CheckCertChain(&chain),
              StatusIs(util::error::FAILED_PRECONDITION));

  // Load CA certs and expect success.
  EXPECT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert));
  EXPECT_OK(checker_.CheckCertChain(&chain));
  EXPECT_EQ(2U, chain.Length());
}

TEST_F(CertCheckerTest, TrimsRepeatedRoots) {
  CertChain chain(leaf_pem_);
  ASSERT_TRUE(chain.IsLoaded());
  ASSERT_TRUE(chain.AddCert(Cert::FromPemString(ca_pem_)));
  ASSERT_TRUE(chain.AddCert(Cert::FromPemString(ca_pem_)));

  // Load CA certs and expect success.
  EXPECT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert));
  EXPECT_OK(checker_.CheckCertChain(&chain));
  EXPECT_EQ(2U, chain.Length());
}

TEST_F(CertCheckerTest, Intermediates) {
  // Load CA certs.
  EXPECT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert));
  // A chain with an intermediate.
  CertChain chain(chain_leaf_pem_);
  ASSERT_TRUE(chain.IsLoaded());
  // Fail as it doesn't chain to a trusted CA.
  EXPECT_THAT(checker_.CheckCertChain(&chain),
              StatusIs(util::error::FAILED_PRECONDITION));
  // Add the intermediate and expect success.
  ASSERT_TRUE(chain.AddCert(Cert::FromPemString(intermediate_pem_)));
  ASSERT_EQ(2U, chain.Length());
  EXPECT_OK(checker_.CheckCertChain(&chain));
  EXPECT_EQ(3U, chain.Length());

  // An invalid chain, with two certs in wrong order.
  CertChain invalid(intermediate_pem_ + chain_leaf_pem_);
  ASSERT_TRUE(invalid.IsLoaded());
  EXPECT_THAT(checker_.CheckCertChain(&invalid),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(CertCheckerTest, PreCert) {
  const string chain_pem = precert_pem_ + ca_pem_;
  PreCertChain chain(chain_pem);

  ASSERT_TRUE(chain.IsLoaded());
  EXPECT_TRUE(chain.IsWellFormed().ValueOrDie());

  // Fail as we have no CA certs.
  string issuer_key_hash, tbs;
  EXPECT_THAT(checker_.CheckPreCertChain(&chain, &issuer_key_hash, &tbs),
              StatusIs(util::error::FAILED_PRECONDITION));

  // Load CA certs and expect success.
  checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert);
  EXPECT_OK(checker_.CheckPreCertChain(&chain, &issuer_key_hash, &tbs));
  string expected_key_hash;
  ASSERT_OK(chain.CertAt(1)->SPKISha256Digest(&expected_key_hash));
  EXPECT_EQ(expected_key_hash, issuer_key_hash);
  // TODO(ekasper): proper KAT tests.
  EXPECT_FALSE(tbs.empty());
}

TEST_F(CertCheckerTest, PreCertWithPreCa) {
  const string chain_pem = precert_with_preca_pem_ + ca_precert_pem_;
  PreCertChain chain(chain_pem);

  ASSERT_TRUE(chain.IsLoaded());
  EXPECT_TRUE(chain.IsWellFormed().ValueOrDie());

  string issuer_key_hash, tbs;
  // Fail as we have no CA certs.
  EXPECT_THAT(checker_.CheckPreCertChain(&chain, &issuer_key_hash, &tbs),
              StatusIs(util::error::FAILED_PRECONDITION));

  // Load CA certs and expect success.
  checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert);
  EXPECT_OK(checker_.CheckPreCertChain(&chain, &issuer_key_hash, &tbs));
  string expected_key_hash;
  ASSERT_OK(chain.CertAt(2)->SPKISha256Digest(&expected_key_hash));
  EXPECT_EQ(expected_key_hash, issuer_key_hash);
  // TODO(ekasper): proper KAT tests.
  EXPECT_FALSE(tbs.empty());

  // A second, invalid chain, with no CA precert.
  PreCertChain chain2(precert_with_preca_pem_);
  ASSERT_TRUE(chain2.IsLoaded());
  EXPECT_TRUE(chain2.IsWellFormed().ValueOrDie());
  EXPECT_THAT(checker_.CheckPreCertChain(&chain2, &issuer_key_hash, &tbs),
              StatusIs(util::error::FAILED_PRECONDITION));
}

TEST_F(CertCheckerTest, CertAsPreCert) {
  ASSERT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert));

  PreCertChain chain(leaf_pem_);
  string issuer_key_hash, tbs;
  EXPECT_THAT(checker_.CheckPreCertChain(&chain, &issuer_key_hash, &tbs),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(CertCheckerTest, PreCertAsCert) {
  ASSERT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert));

  const string chain_pem = precert_pem_ + ca_pem_;
  PreCertChain chain(chain_pem);
  EXPECT_THAT(checker_.CheckCertChain(&chain),
              StatusIs(util::error::INVALID_ARGUMENT));
}

// Accept if the root cert has no CA:True constraint and is in the trust store.
// Also accept MD2 in root cert.
TEST_F(CertCheckerTest, AcceptNoBasicConstraintsAndMd2) {
  ASSERT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaNoBCCert));

  string ca_pem;
  ASSERT_TRUE(util::ReadTextFile(cert_dir_ + "/" + kCaNoBCCert, &ca_pem));
  const unique_ptr<Cert> ca(Cert::FromPemString(ca_pem));
  ASSERT_TRUE(ca.get());
  // Verify testdata properties: CA is legacy root.
  ASSERT_EQ("md2WithRSAEncryption", ca->PrintSignatureAlgorithm());
  ASSERT_FALSE(ca->HasBasicConstraintCATrue().ValueOrDie());

  string chain_pem;
  ASSERT_TRUE(util::ReadTextFile(cert_dir_ + "/" + kNoBCChain, &chain_pem));

  CertChain chain(chain_pem);
  ASSERT_TRUE(chain.IsLoaded());

  EXPECT_OK(checker_.CheckCertChain(&chain));
}

// Don't accept if some other cert without CA:True tries to issue.
TEST_F(CertCheckerTest, DontAcceptNoBasicConstraints) {
  ASSERT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert));

  string chain_pem;
  ASSERT_TRUE(util::ReadTextFile(cert_dir_ + "/" + kBadNoBCChain, &chain_pem));

  CertChain chain(chain_pem);
  ASSERT_TRUE(chain.IsLoaded());
  EXPECT_THAT(checker_.CheckCertChain(&chain),
              StatusIs(util::error::INVALID_ARGUMENT));
}

// Don't accept if anything else but the trusted root is signed with MD2.
TEST_F(CertCheckerTest, DontAcceptMD2) {
  ASSERT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaNoBCCert));

  string chain_pem;
  ASSERT_TRUE(util::ReadTextFile(cert_dir_ + "/" + kMd2Chain, &chain_pem));

  CertChain chain(chain_pem);
  ASSERT_TRUE(chain.IsLoaded());
  // Verify testdata properties: chain terminates in an MD2 intermediate.
  ASSERT_FALSE(chain.LastCert()->IsSelfSigned().ValueOrDie());
  ASSERT_TRUE(chain.LastCert()->HasBasicConstraintCATrue().ValueOrDie());
  ASSERT_EQ("md2WithRSAEncryption",
            chain.LastCert()->PrintSignatureAlgorithm());

#ifdef OPENSSL_NO_MD2
  EXPECT_THAT(checker_.CheckCertChain(&chain),
              StatusIs(util::error::INVALID_ARGUMENT));
#else
  LOG(WARNING) << "Skipping test: MD2 is enabled! You should configure "
               << "OpenSSL with -DOPENSSL_NO_MD2 to be safe!";
#endif
}

TEST_F(CertCheckerTest, ResolveIssuerCollisions) {
  string chain_pem, root1_pem, root2_pem;
  ASSERT_TRUE(
      util::ReadTextFile(cert_dir_ + "/" + kCollisionChain, &chain_pem));

  ASSERT_TRUE(
      checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCollisionRoot1));
  ASSERT_TRUE(
      checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCollisionRoot2));
  CertChain chain(chain_pem);
  ASSERT_TRUE(chain.IsLoaded());
  EXPECT_OK(checker_.CheckCertChain(&chain));

  // The same, but include the root in the submission.
  ASSERT_TRUE(
      util::ReadTextFile(cert_dir_ + "/" + kCollisionRoot1, &root1_pem));
  ASSERT_TRUE(
      util::ReadTextFile(cert_dir_ + "/" + kCollisionRoot2, &root2_pem));
  CertChain chain1(chain_pem);
  ASSERT_TRUE(chain1.AddCert(Cert::FromPemString(root1_pem)));
  EXPECT_OK(checker_.CheckCertChain(&chain1));

  CertChain chain2(chain_pem);
  ASSERT_TRUE(chain2.AddCert(Cert::FromPemString(root2_pem)));
  EXPECT_OK(checker_.CheckCertChain(&chain2));
}

TEST_F(CertCheckerTest, TestDsaPrecertFailsRootNotTrusted) {
  // Load CA certs.
  EXPECT_TRUE(checker_.LoadTrustedCertificates(cert_dir_ + "/" + kCaCert));
  PreCertChain pre_chain(kDsaPrecertChain);
  string issuer_key_hash, tbs;

  // With our default roots this should not be accepted, but it shouldn't
  // fail with an algorithm related error
  const util::Status status(
      checker_.CheckPreCertChain(&pre_chain, &issuer_key_hash, &tbs));

  EXPECT_THAT(status,
              StatusIs(util::error::FAILED_PRECONDITION, "unknown root"));
}

TEST_F(CertCheckerTest, TestDsaPrecertChain) {
  // Explicitly set the root of this chain as trusted
  vector<string> roots;
  roots.push_back(kDsaPrecertChainRootOnly);
  checker_.LoadTrustedCertificates(roots);

  PreCertChain pre_chain(kDsaPrecertChain);
  string issuer_key_hash, tbs;

  EXPECT_OK(checker_.CheckPreCertChain(&pre_chain, &issuer_key_hash, &tbs));
  // Added a root CA.
  EXPECT_EQ(2U, pre_chain.Length());
  // And set a SHA256 HASH
  EXPECT_EQ(32U, issuer_key_hash.size());
  // And the TBS fields
  EXPECT_FALSE(tbs.empty());
}

TEST_F(CertCheckerTest, TestDsaPrecertChainRejectsInvalidDsaSig) {
  // Explicitly set the root of this chain as trusted
  vector<string> roots;
  roots.push_back(kDsaPrecertChainRootOnly);
  checker_.LoadTrustedCertificates(roots);

  // This has a deliberately corrupt signature
  PreCertChain pre_chain(kDsaPrecertChainInvalidSig);
  string issuer_key_hash, tbs;

  const util::Status status(
        checker_.CheckPreCertChain(&pre_chain, &issuer_key_hash, &tbs));

  EXPECT_THAT(status, StatusIs(util::error::INVALID_ARGUMENT,
                               "invalid certificate chain"));
}

}  // namespace

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  cert_trans::LoadCtExtensions();
  return RUN_ALL_TESTS();
}
