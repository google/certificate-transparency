package org.certificatetransparency.ctlog;

/**
 * Indicate basic crypto primitive (X.509, SHA-256, EC) not supported by this platform.
 */
public class UnsupportedCryptoPrimitiveException extends CertificateTransparencyException {
  public UnsupportedCryptoPrimitiveException(String message, Throwable cause) {
    super(message, cause);
  }
}
