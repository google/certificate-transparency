package org.certificatetransparency.ctlog;

import com.google.common.io.Files;
import org.certificatetransparency.ctlog.serialization.CryptoDataLoader;
import org.certificatetransparency.ctlog.serialization.Deserializer;
import org.certificatetransparency.ctlog.proto.Ct;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;


/**
 * This test verifies that the data is correctly serialized for signature comparison, so
 * signature verification is actually effective.
 */
@RunWith(JUnit4.class)
public class LogSignatureVerifierTest {
  public static final String TEST_CERT = "test/testdata/test-cert.pem";
  public static final String TEST_CERT_SCT = "test/testdata/test-cert.proof";
  public static final String TEST_LOG_KEY = "test/testdata/ct-server-key-public.pem";

  @Test
  public void signatureVerifies() throws IOException, CertificateException,
      InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    List<Certificate> certs = CryptoDataLoader.certificatesFromFile(new File(TEST_CERT));
    Ct.SignedCertificateTimestamp sct = Deserializer.parseSCTFromBinary(
        new ByteArrayInputStream(Files.toByteArray(new File(TEST_CERT_SCT))));
    LogInfo logInfo = LogInfo.fromKeyFile(TEST_LOG_KEY);
    LogSignatureVerifier verifier = new LogSignatureVerifier(logInfo);
    verifier.verifySignature(sct, certs.get(0));
  }
}
