package org.certificatetransparency.ctlog.comm;

import org.certificatetransparency.ctlog.CertificateTransparencyException;

/**
 * Indicates the log was unreadable  - HTTP communication with it was not possible or response could not be processed.
 */
public class LogCommunicationException extends CertificateTransparencyException {
  public LogCommunicationException(String message) {
    super(message);
  }

  public LogCommunicationException(String message, Throwable cause) {
    super(message, cause);
  }

}
