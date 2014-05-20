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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
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

	public static void main(String[] args) throws Exception {
		try {
			if (args.length < 3) {
				LOG.error(String.format("Usage: %s <command> <Log URL> <Log public key> [<params>...]", CTLogClient.class.getSimpleName()));
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

	private void retrieve(String strStart, String strEnd, String outputFile) throws Exception {
		boolean all = "all".equalsIgnoreCase(strStart);
		int start = all ? 0 : Integer.parseInt(strStart);
		int end = all ? getSize() - 1 : strEnd != null ? Integer.parseInt(strEnd) : start + 1;
		Stopwatch timer = Stopwatch.createStarted();
		httpClient.getLogEntries(end - 1, end);
		CertificateDataSet logEntries = httpClient.getLogEntries(start, end);
		timer.stop();
		LOG.info(String.format("Retrieved %d log entries in %s seconds.", logEntries.getDataSet().size(), timer.elapsed(TimeUnit.SECONDS)));

		if (outputFile != null)
			try (ObjectOutput objectOutput = new ObjectOutputStream(new FileOutputStream(outputFile, false))) {
				objectOutput.writeObject(logEntries.getDataSet());
				LOG.info(String.format("Saved log entries to file '%s'.", outputFile));
			}
	}

	private int getSize() {
		return httpClient.getSize();
	}

	private static String getBaseUrl(String url) {
		return String.format("%s/ct/v1/", url);
	}
}
