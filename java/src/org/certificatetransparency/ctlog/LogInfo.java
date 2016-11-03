package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.serialization.CryptoDataLoader;

import com.google.common.io.BaseEncoding;

import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Holds information about the log: Mainly, its public key and log ID (which is calculated
 * from the Log ID).
 * Ideally created from a file with the Log's public key in PEM encoding.
 */
public class LogInfo {
  private final PublicKey logKey;
  private final byte[] logId;

  /**
   * C'tor.
   *
   * @param logKey Public key of the log.
   */
  public LogInfo(PublicKey logKey) {
    this.logKey = logKey;
    logId = calculateLogId(logKey);
  }

  byte[] getID() {
    return logId;
  }

  public PublicKey getKey() {
    return logKey;
  }

  public String getSignatureAlgorithm() {
    return logKey.getAlgorithm();
  }

  public boolean isSameLogId(byte[] idToCheck) {
    return Arrays.equals(getID(), idToCheck);
  }

  private static byte[] calculateLogId(PublicKey logKey) {
    try {
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      sha256.update(logKey.getEncoded());
      final byte[] sha256result = sha256.digest();
      System.out.println("SHA256 of key:" + bytesToHex(sha256result));
      return sha256result;

    } catch (NoSuchAlgorithmException e) {
      throw new UnsupportedCryptoPrimitiveException("Missing SHA-256", e);
    }
  }

  /**
   * Convert bytes to string of upper case hex digits.
   */
  public static String bytesToHex(byte[] bytes) {
    return BaseEncoding.base16().encode(bytes);
  }

  /**
   * Creates a LogInfo instance from the Log's public key file.
   *
   * @param pemKeyFilePath Path of the log's public key file.
   * @return new LogInfo instance.
   */
  public static LogInfo fromKeyFile(String pemKeyFilePath) {
    PublicKey logPublicKey = CryptoDataLoader.keyFromFile(new File(pemKeyFilePath));
    return new LogInfo(logPublicKey);
  }
}
