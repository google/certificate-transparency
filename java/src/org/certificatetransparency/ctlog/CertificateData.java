package org.certificatetransparency.ctlog;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.certificatetransparency.ctlog.proto.Ct;

import com.google.common.base.Preconditions;

/**
 * CT data object.
 */
public class CertificateData implements Serializable, Comparable<CertificateData> {
  private static final long serialVersionUID = 1L;

  private final Ct.LogEntryType type;

  private final X509CertificateObject certificate;

  private final TBSCertificate preCertificate;

  private final byte[] extensions;

  private final List<X509CertificateObject> extraCertificates;

  /**
   * Create a new CertificateData object with the parameters passed verifying the validity.
   */
  public static CertificateData newData(Ct.LogEntryType type, X509CertificateObject certificate,
      TBSCertificate preCertificate, byte[] extensions, List<X509CertificateObject> extraCertificates) {
    Preconditions.checkArgument((type == Ct.LogEntryType.X509_ENTRY && certificate != null || type == Ct.LogEntryType.PRECERT_ENTRY
                && preCertificate != null)
                && (preCertificate == null ^ certificate == null),
            "The certificate cannot be null for X509 entry types or the preCertificate "
            + "cannot be null for pre-certificate entry types.");
    return new CertificateData(type, certificate, preCertificate, extensions, extraCertificates);
  }

  protected CertificateData(Ct.LogEntryType type, X509CertificateObject certificate,
      TBSCertificate preCertificate, byte[] extensions,
      List<X509CertificateObject> extraCertificates) {
    this.type = type;
    this.certificate = certificate;
    this.preCertificate = preCertificate;
    this.extensions = extensions;
    this.extraCertificates = extraCertificates;
  }

  public Ct.LogEntryType getType() {
    return type;
  }

  public X509CertificateObject getCertificate() {
    return certificate;
  }

  public TBSCertificate getPreCertificate() {
    return preCertificate;
  }

  public byte[] getExtensions() {
    return extensions;
  }

  public List<X509CertificateObject> getExtraCertificates() {
    return extraCertificates;
  }

  @Override
  public int hashCode() {
    return Objects.hash(type, certificate, extraCertificates, extensions.length);
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof CertificateData && compareTo((CertificateData) other) == 0;
  }

  @Override
  public int compareTo(CertificateData other) {
    if (!Objects.equals(type, other.getType()))
      return type.ordinal() - other.getType().ordinal();
    else if (!Objects.equals(certificate, other.getCertificate()))
      return Objects.hash(certificate) - Objects.hash(other.getCertificate());
    else if (!Objects.equals(preCertificate, other.getPreCertificate()))
      return Objects.hash(preCertificate) - Objects.hash(other.getPreCertificate());
    else if (!Objects.equals(extraCertificates, other.getExtraCertificates()))
      return Objects.hash(extraCertificates) - Objects.hash(other.getExtraCertificates());
    else if (!Arrays.equals(extensions, other.getExtensions()))
      return Arrays.hashCode(extensions) - Arrays.hashCode(other.extensions);

    return 0;
  }
}
