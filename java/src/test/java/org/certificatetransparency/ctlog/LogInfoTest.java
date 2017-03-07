package org.certificatetransparency.ctlog;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.assertTrue;

/**
 * Mostly for verifying the log info calculates the log ID correctly.
 */
@RunWith(JUnit4.class)
public class LogInfoTest {
  /** EC log key */
  public static final byte[] PUBLIC_KEY = Base64.decodeBase64(
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV"
          + "4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==");
  public static final byte[] LOG_ID =
      Base64.decodeBase64("pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=");

  /** RSA log key */
  public static final byte[] PUBLIC_KEY_RSA = Base64.decodeBase64(
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3tyLdYQYM+K+1jGlLUTJ"
          + "lNFTeNJM4LN5ctwAwXDhoKCFJrGAayZaXJsYtKHf+RH2Y6pqbtE4Ln/4HgXXzFQi"
          + "BuyTed/ooAafYkDPQsrg51/DxV4WZG66WzFjbFtBPKVfSnLqmbhRlr99PEY92bDt"
          + "8YUOCfEikqHIDZaieJHQQlIx5yjOYbRnsBT0HDitTuvM1or589k+wnYVyNEtU9Np"
          + "NA+37kBD0SM7LipYCCSrb0zh5yTriNQS/LmdUWE1G5v8VR+acttDl5zPKetocNMg"
          + "7NIa/zvrXizld9DQqt2UiC49KcD9x2shxEgp64K0S0546kU0lKYnY7NimDkVRCOe"
          + "3wIDAQAB");
  public static final byte[] LOG_ID_RSA = Base64.decodeBase64(
          "oCQsumIkVhezsKvGJ+spTJIM9H+jy/OdvSGDIX0VsgY=");

  static PublicKey getKey(byte[] keyBytes, String keyAlg) {
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    try {
      KeyFactory kf = KeyFactory.getInstance(keyAlg);
      return kf.generatePublic(spec);
    } catch (InvalidKeySpecException e) {
      throw new RuntimeException(e);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void testCalculatesLogIdCorrectly() {
    LogInfo logInfo = new LogInfo(getKey(PUBLIC_KEY, "EC"));
    assertTrue(logInfo.isSameLogId(LOG_ID));
  }

  @Test
  public void testCalculatesLogIdCorrectlyRSA() {
    LogInfo logInfo = new LogInfo(getKey(PUBLIC_KEY_RSA, "RSA"));
    assertTrue(logInfo.isSameLogId(LOG_ID_RSA));
  }
}
