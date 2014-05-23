package org.certificatetransparency.ctlog.comm;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.apache.commons.codec.binary.Base64;
import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.serialization.CryptoDataLoader;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Matchers;

import java.io.File;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;


/**
 * Test interaction with the Log http server.
 */
@RunWith(JUnit4.class)
public class HttpLogClientTest {
  public static final String TEST_DATA_PATH = "test/testdata/test-colliding-roots.pem";

  public static final String JSON_RESPONSE = ""
      + "{\"sct_version\":0,\"id\":\"pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=\","
      + "\"timestamp\":1373015623951,\n"
      + "\"extensions\":\"\",\n"
      + "\"signature\":\"BAMARjBEAiAggPtKUMFZ4zmNnPhc7As7VR1Dedsdggs9a8pSEHoyGAIgKGsvIPDZg"
      + "DnxTjGY8fSBwkl15dA0TUqW5ex2HCU7yE8=\"}";

  public static final byte[] LOG_ID =
      Base64.decodeBase64("pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=");

  @Test
  public void certificatesAreEncoded() throws CertificateException, IOException {
    List<Certificate> inputCerts = CryptoDataLoader.certificatesFromFile(new File(TEST_DATA_PATH));
    HttpLogClient client = new HttpLogClient("");

    JSONObject encoded = client.encodeCertificates(inputCerts);
    Assert.assertTrue(encoded.containsKey("chain"));
    JSONArray chain = (JSONArray) encoded.get("chain");
    assertEquals("Expected to have two certificates in the chain", 2, chain.size());
    // Make sure the order is reversed.
    for (int i = 0; i < inputCerts.size(); i++) {
      assertEquals(
          Base64.encodeBase64String(inputCerts.get(i).getEncoded()),
          chain.get(i));
    }
  }

  public void verifySCTContents(Ct.SignedCertificateTimestamp sct) {
    assertEquals(Ct.Version.V1, sct.getVersion());
    assertArrayEquals(LOG_ID, sct.getId().getKeyId().toByteArray());
    assertEquals(1373015623951L, sct.getTimestamp());
    assertEquals(Ct.DigitallySigned.HashAlgorithm.SHA256, sct.getSignature().getHashAlgorithm());
    assertEquals(Ct.DigitallySigned.SignatureAlgorithm.ECDSA, sct.getSignature().getSigAlgorithm());
  }
  @Test
  public void serverResponseParsed() throws IOException {
    Ct.SignedCertificateTimestamp sct = HttpLogClient.parseServerResponse(JSON_RESPONSE);
    verifySCTContents(sct);
  }

  @Test
  public void certificateSentToServer() throws IOException, CertificateException {
    HttpPostInvoker mockInvoker = mock(HttpPostInvoker.class);
    when(mockInvoker.makePostRequest(eq("http://ctlog/add-chain"), Matchers.anyString()))
      .thenReturn(JSON_RESPONSE);

    HttpLogClient client = new HttpLogClient("http://ctlog/", mockInvoker);
    List<Certificate> certs = CryptoDataLoader.certificatesFromFile(new File(TEST_DATA_PATH));
    Ct.SignedCertificateTimestamp res = client.addCertificate(certs);
    assertNotNull("Should have a meaningful SCT", res);

    verifySCTContents(res);
  }
}
