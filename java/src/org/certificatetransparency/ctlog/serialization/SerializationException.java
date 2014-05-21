package org.certificatetransparency.ctlog.serialization;

import org.certificatetransparency.ctlog.CertificateTransparencyException;

/**
 * Error serializing / deserializing data.
 */
@SuppressWarnings("serial")
public class SerializationException extends CertificateTransparencyException {
  public SerializationException(String message) {
    super(message);
  }

  public SerializationException(String message, Throwable cause) {
    super(message, cause);
  }
}
