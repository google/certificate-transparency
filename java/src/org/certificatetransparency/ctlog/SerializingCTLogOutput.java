package org.certificatetransparency.ctlog;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Saves the {@link CertificateData} entries in serialized form.
 */
public class SerializingCTLogOutput implements CTLogOutput {
  private static final Log LOG = LogFactory.getLog(SerializingCTLogOutput.class);

  private final CertificateDataSet data = new CertificateDataSet();

  @Override
  public void save() throws IOException {
    String outputFile = "ct_log_output." + new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
    try (ObjectOutput objectOutput = new ObjectOutputStream(new FileOutputStream(outputFile, false))) {
      objectOutput.writeObject(data.getDataSet());
      LOG.info(String.format("Saved log entries to file '%s'.", outputFile));
    }
  }

  @Override
  public boolean addAll(Collection<CertificateData> entries, long startEntryId, long endEntryId) {
    return data.addAll(entries);
  }

  @Override
  public int getSize() {
    return data.getDataSet().size();
  }

  /**
   * @return the underlying data set.
   */
  public Collection<CertificateData> getData() {
    return data.getDataSet();
  }
}
