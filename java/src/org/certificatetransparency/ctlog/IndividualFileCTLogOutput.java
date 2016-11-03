package org.certificatetransparency.ctlog;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.encoders.Hex;
import org.certificatetransparency.ctlog.proto.Ct;

import com.google.common.collect.Maps;

/**
 * Saves the {@link CertificateData} entries in a directory structure containing each certificate in a single file.
 */
public class IndividualFileCTLogOutput implements CTLogOutput {
  private static final Object VALUE = new Object();
  private static final Log LOG = LogFactory.getLog(IndividualFileCTLogOutput.class);

  private final File cACertDirectory;
  private final File certDirectory;

  private final AtomicInteger size = new AtomicInteger(0);

  private final ConcurrentMap<List<X509CertificateObject>, Object> caCerts = Maps.newConcurrentMap();

  public IndividualFileCTLogOutput() {
    File mainDirectory = createDirectory();
    cACertDirectory = new File(mainDirectory, "caCerts");
    certDirectory = new File(mainDirectory, "certs");
    cACertDirectory.mkdirs();
    certDirectory.mkdir();
    new File(certDirectory, "other").mkdir();
    new File(cACertDirectory, "other").mkdir();
    makeSubDirs(certDirectory, 'a', 'z');
    makeSubDirs(certDirectory, 'A', 'Z');
    makeSubDirs(certDirectory, '0', '9');
  }

  private void makeSubDirs(File mainDirectory, char start, char end) {
    for (char c = start; c <= end; c++) {
      File dir = new File(mainDirectory, "" + c);
      dir.mkdirs();
    }
  }

  private File createDirectory() {
    String dirName = "ct_log_output_" + new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
    return new File(dirName);
  }

  @Override
  public void save() throws IOException {
    for (List<X509CertificateObject> chain : caCerts.keySet())
      saveCertificates(cACertDirectory, chain.toArray(new X509CertificateObject[0]));

    LOG.info(String.format("%d certificates saved in %s", size.get(), certDirectory.getCanonicalPath()));
  }

  @Override
  public boolean addAll(Collection<CertificateData> entries, long startEntryId, long endEntryId) {
    return saveBatch(entries);
  }

  private boolean saveCertificates(File directory, TBSCertificate ... certs) {
    for (TBSCertificate cert : certs)
      try {
        saveCert(directory,
            getCertFileName(cert.getIssuer().toString(),
                cert.getSubject().toString(),
                cert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes(),
                cert.getSerialNumber().getValue()),
            cert.getEncoded());
      } catch (IOException e) {
        LOG.warn("Failed to save a certificate", e);
      }
    return true;
  }

  private boolean saveCertificates(File directory, X509CertificateObject ... certs) {
    for (X509CertificateObject cert : certs)
      try {
        PublicKey publicKey = cert.getPublicKey();
        JcaX509CertificateHolder certificateHolder = new JcaX509CertificateHolder(cert);
        X500Name issuer = certificateHolder.getIssuer();
        X500Name subject = certificateHolder.getSubject();
        saveCert(directory,
            getCertFileName(getValue(issuer, BCStyle.OU, BCStyle.O),
                getValue(subject, BCStyle.CN, BCStyle.OU, BCStyle.O),
                publicKey != null ? publicKey.getEncoded() : null,
                cert.getSerialNumber()),
            cert.getEncoded());
      } catch (IOException | CertificateEncodingException e) {
        LOG.warn("Failed to save a certificate", e);
      }

    return true;
  }

  private String getValue(X500Name x500name, ASN1ObjectIdentifier... ids) {
    for (ASN1ObjectIdentifier id : ids) {
      RDN[] RDNs = x500name.getRDNs(id);
      if (RDNs.length > 0)
        return IETFUtils.valueToString(RDNs[0].getFirst().getValue());
    }

    return "";
  }

  /**
   * @return <issuer>_<subject>_<public_key>_<serial_number>
   */
  private String getCertFileName(String issuer, String subject, byte[] publicKey, BigInteger serialNumber) {
    String fileName = String.format("%s_%s_%s_%s", issuer, subject, serialNumber.toString(16), publicKey != null ? getSHA1(publicKey) : "0x0").replaceAll("[\\/\\\\:]", "_");

    if (fileName.startsWith("http___"))
      fileName = fileName.substring(7);

    if (fileName.startsWith("_"))
      fileName = fileName.substring(1);

    if (fileName.startsWith("*."))
      fileName = fileName.substring(2);

    return fileName;
  }

  private void saveCert(File directory, String fileName, byte[] encoded) throws IOException {
    File dir = new File(directory, "" + fileName.charAt(0));
    File file = new File(dir, fileName);

    if (!dir.exists()) {
      dir = new File(directory, "other");
      file = new File(dir, fileName);
    }

    try {
      LOG.info("Filename: " + fileName);
      file.createNewFile();
      try (FileOutputStream fos = new FileOutputStream(file)) {
        fos.write(encoded);
        fos.flush();
      }
    } catch (IOException e) {
      if (e.getMessage().contains("No space left on device"))
        synchronized(this) {
          LOG.error("File: '" + fileName + "'", e);
          System.exit(-1);
        }
      throw e;
    }
  }

  private String getSHA1(byte[] bytes) {
    SHA1Digest digest = new SHA1Digest();
    digest.update(bytes, 0, bytes.length);
    byte[] out = new byte[digest.getDigestSize()];
    digest.doFinal(out, 0);
    return Hex.toHexString(out);
  }

  private boolean saveBatch(Collection<CertificateData> entries) {
    boolean result = false;
    for (CertificateData entry : entries) {
      result = entry.getType() == Ct.LogEntryType.X509_ENTRY
          ? saveCertificates(certDirectory, entry.getCertificate())
          : saveCertificates(certDirectory, entry.getPreCertificate());

      List<X509CertificateObject> chain = CertificateDataSet.getSingletonList(entry.getExtraCertificates());
      caCerts.putIfAbsent(chain, VALUE);
    }

    size.addAndGet(entries.size());

    return result;
  }

  @Override
  public int getSize() {
    return size.get();
  }
}
