package org.certificatetransparency.ctlog;

/**
 * Base class for CT errors.
 */
public class CertificateTransparencyException extends RuntimeException {
  public CertificateTransparencyException(String message) {
    super(message);
  }

  public CertificateTransparencyException(String message, Throwable cause) {
    super(message + ": " + cause.getMessage(), cause);
  }
}
