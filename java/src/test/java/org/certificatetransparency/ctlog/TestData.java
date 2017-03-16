package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.serialization.CryptoDataLoader;
import org.junit.Ignore;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.security.cert.Certificate;
import java.util.List;

/**
 * Constants for tests.
 */
@Ignore
public class TestData {
  private static final String DATA_ROOT = "/testdata/";
  // Public log key
  public static final String TEST_LOG_KEY = DATA_ROOT + "ct-server-key-public.pem";
  public static final String TEST_LOG_KEY_RSA = DATA_ROOT + "rsa/ct-server-key-public-rsa.pem";
  // Root CA cert.
  public static final String ROOT_CA_CERT = DATA_ROOT + "ca-cert.pem";
  // Ordinary cert signed by ca-cert, with SCT served separately.
  public static final String TEST_CERT = DATA_ROOT + "test-cert.pem";
  public static final String TEST_CERT_SCT = DATA_ROOT + "test-cert.proof";
  public static final String TEST_CERT_SCT_RSA = DATA_ROOT + "rsa/test-cert-rsa.proof";
  // PreCertificate signed by ca-cert.
  public static final String TEST_PRE_CERT = DATA_ROOT + "test-embedded-pre-cert.pem";
  public static final String TEST_PRE_SCT = DATA_ROOT + "test-embedded-pre-cert.proof";
  public static final String TEST_PRE_SCT_RSA = DATA_ROOT + "rsa/test-embedded-pre-cert-rsa.proof";
  // PreCertificate Signing cert, signed by ca-cert.pem
  public static final String PRE_CERT_SIGNING_CERT = DATA_ROOT + "ca-pre-cert.pem";
  // PreCertificate signed by the PreCertificate Signing Cert above.
  public static final String TEST_PRE_CERT_SIGNED_BY_PRECA_CERT =
      DATA_ROOT + "test-embedded-with-preca-pre-cert.pem";
  public static final String TEST_PRE_CERT_PRECA_SCT =
      DATA_ROOT + "test-embedded-with-preca-pre-cert.proof";
  // intermediate CA cert signed by ca-cert
  public static final String INTERMEDIATE_CA_CERT = DATA_ROOT + "intermediate-cert.pem";
  // Certificate signed by intermediate CA.
  public static final String TEST_INTERMEDIATE_CERT = DATA_ROOT + "test-intermediate-cert.pem";
  public static final String TEST_INTERMEDIATE_CERT_SCT =
      DATA_ROOT + "test-intermediate-cert.proof";

  public static final String TEST_PRE_CERT_SIGNED_BY_INTERMEDIATE =
      DATA_ROOT + "test-embedded-with-intermediate-pre-cert.pem";
  public static final String TEST_PRE_CERT_SIGNED_BY_INTERMEDIATE_SCT =
      DATA_ROOT + "test-embedded-with-intermediate-pre-cert.proof";

  public static final String PRE_CERT_SIGNING_BY_INTERMEDIATE =
      DATA_ROOT + "intermediate-pre-cert.pem";
  public static final String TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE =
      DATA_ROOT + "test-embedded-with-intermediate-preca-pre-cert.pem";
  public static final String TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE_SCT =
      DATA_ROOT + "test-embedded-with-intermediate-preca-pre-cert.proof";
  public static final String TEST_ROOT_CERTS = DATA_ROOT + "test-root-certs";

  static List<Certificate> loadCertificates(String filename) {
    File file = new File(TestData.class.getResource(filename).getFile());
    return CryptoDataLoader.certificatesFromFile(file);
  }

  public static FileReader fileReader(String name) throws FileNotFoundException {
    return new FileReader(TestData.class.getResource(name).getFile());
  }

  public static File file(String name) {
    return new File(TestData.class.getResource(name).getFile());
  }

  public static String fileName(String name) {
    return TestData.class.getResource(name).getFile();
  }
}
