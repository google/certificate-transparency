package org.certificatetransparency.ctlog;

import com.google.common.base.Stopwatch;
import com.google.common.io.Files;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.certificatetransparency.ctlog.comm.HttpLogClient;
import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.serialization.CryptoDataLoader;
import org.certificatetransparency.ctlog.serialization.Serializer;

import java.io.File;
import java.io.IOException;
import java.security.cert.Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * The main CT log client. Currently only knows how to upload certificate chains
 * to the ctlog.
 */
public class CTLogClient {
  private static final Log LOG = LogFactory.getLog(CTLogClient.class);
  private final HttpLogClient httpClient;
  private final LogSignatureVerifier signatureVerifier;

  /**
   * Result of the certificate upload. Contains the SCT and verification result.
   */
  public static class UploadResult {
    private final Ct.SignedCertificateTimestamp sct;
    private final boolean verified;

    public UploadResult(Ct.SignedCertificateTimestamp sct, boolean verified) {
      this.sct = sct;
      this.verified = verified;
    }

    public boolean isVerified() {
      return verified;
    }

    public final Ct.SignedCertificateTimestamp getSct() {
      return sct;
    }
  }

  public CTLogClient(String baseLogUrl, LogInfo logInfo) {
    this.httpClient = new HttpLogClient(baseLogUrl);
    this.signatureVerifier = new LogSignatureVerifier(logInfo);
  }

  public UploadResult uploadCertificatesChain(List<Certificate> chain) {
    Ct.SignedCertificateTimestamp sct = httpClient.addCertificate(chain);
    return new UploadResult(sct, signatureVerifier.verifySignature(sct, chain.get(0)));
  }

  public static void main(String[] args) throws IOException {
    try {
      if (args.length < 3) {
        LOG.error(String.format("Usage: %s <command> <Log URL> <Log public key> [<params>...]",
            CTLogClient.class.getSimpleName()));
        LOG.error("Commands - add, retrieve");
        LOG.error("add command parameters - <Certificate chain> [output file]");
        LOG.error("retrieve command parameters - <start> [<end>]");
        return;
      }

      String command = args[0];
      String logUrl = getBaseUrl(args[1]);
      String logPublicKeyFile = args[2];
      CTLogClient client = new CTLogClient(logUrl, LogInfo.fromKeyFile(logPublicKeyFile));

      String arg4 = args.length > 4 ? args[4] : null;
      if ("add".equals(command))
        client.uploadCertificates(args[3], arg4);
      else if ("retrieve".equals(command))
        client.retrieve(args[3], arg4, args.length > 5 ? args[5] : null);
    } catch (Throwable e) {
      LOG.error(e);
      System.exit(-1);
    }

    System.exit(0);
  }

  private void uploadCertificates(String pemFile, String outputSctFile) throws IOException {
    List<Certificate> certs = CryptoDataLoader.certificatesFromFile(new File(pemFile));
    LOG.info(String.format("Total number of certificates: %d", certs.size()));

    UploadResult result = uploadCertificatesChain(certs);
    if (result.isVerified()) {
      LOG.info("Upload successful ");
      if (outputSctFile != null) {
        byte[] serialized = Serializer.serializeSctToBinary(result.getSct());
        Files.write(serialized, new File(outputSctFile));
      }
    } else {
      LOG.info("Log signature verification FAILED.");
    }
  }

  private void retrieve(String strStart, String strEnd, String entryProcessor) throws Exception {
    boolean all = "all".equalsIgnoreCase(strStart);
    long start = all ? 0 : Long.parseLong(strStart);
    long end = all ? getTreeSize() - 1 : strEnd != null ? Long.parseLong(strEnd) : start + 1;
    Stopwatch timer = Stopwatch.createStarted();

    CTLogOutput output;

    if (entryProcessor != null) {
      output = (CTLogOutput) Class.forName(entryProcessor).newInstance();
    } else {
      output = new SerializingCTLogOutput();
    }

    httpClient.getLogEntries(start, end, output);
    timer.stop();
    LOG.info(String.format("Retrieved %d log entries in %s seconds.", output.getSize(), timer.elapsed(TimeUnit.SECONDS)));

    output.save();
  }

  private long getTreeSize() {
    return httpClient.getTreeSize();
  }

  private static String getBaseUrl(String url) {
    return String.format("%s/ct/v1/", url);
  }
}
