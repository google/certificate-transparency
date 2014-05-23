package org.certificatetransparency.ctlog;

/**
 * Indicate basic crypto primitive (X.509, SHA-256, EC) not supported by this platform.
 */
@SuppressWarnings("serial")
public class UnsupportedCryptoPrimitiveException extends CertificateTransparencyException {
  public UnsupportedCryptoPrimitiveException(String message, Throwable cause) {
    super(message, cause);
  }
}
