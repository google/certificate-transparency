package org.certificatetransparency.ctlog;

import java.io.IOException;
import java.util.Collection;

/**
 * Helper interface for saving output from CT Log Client.
 * Implementations <b>MUST</b> be thread safe.
 */
public interface CTLogOutput {
  /**
   * Save the output.
   */
  void save() throws IOException;

  /**
   * Add a collection of entries to the output.
   */
  boolean addAll(Collection<CertificateData> entries, long startEntryId, long endEntryId);

  /**
   * @return the number of entries saved.
   */
  int getSize();
}
