package org.certificatetransparency.ctlog;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

public class CertificateDataSet implements Serializable {
  private static final long serialVersionUID = 1L;

  private static final Log LOG = LogFactory.getLog(CertificateDataSet.class);

  private static final ConcurrentMap<X509CertificateObject, X509CertificateObject> X509_CERTIFICATES =
      Maps.newConcurrentMap();

  private static final ConcurrentMap<List<X509CertificateObject>, List<X509CertificateObject>> X509_CHAINS =
      Maps.newConcurrentMap();

  private static final ConcurrentMap<TBSCertificate, TBSCertificate> TBS_CERTIFICATES = Maps
      .newConcurrentMap();

  private Set<CertificateData> dataSet = Sets.newHashSet();

  public static X509CertificateObject getSingletonX509Certificate(X509CertificateObject certificate) {
    return addOrGet(X509_CERTIFICATES, certificate);
  }

  public static TBSCertificate getSingletonTBSCertificate(TBSCertificate certificate) {
    return addOrGet(TBS_CERTIFICATES, certificate);
  }

  private List<X509CertificateObject> getSingletonList(List<X509CertificateObject> chain) {
    return addOrGet(
        X509_CHAINS,
        chain.stream().map(v -> getSingletonX509Certificate(v))
            .collect(Collectors.toCollection(new Supplier<List<X509CertificateObject>>() {
              @Override
              public List<X509CertificateObject> get() {
                return new ArrayList<X509CertificateObject>(chain.size());
              }
            })));
  }

  private static <X> X addOrGet(ConcurrentMap<X, X> certMap, X certificate) {
    return certificate != null ? certMap.computeIfAbsent(certificate, certtificate -> certificate)
        : null;
  }

  public void addAll(Collection<CertificateData> cds) {
    dataSet.addAll(cds
        .stream()
        .map(
            data -> new CertificateData(data.getType(), getSingletonX509Certificate(data
                .getCertificate()), getSingletonTBSCertificate(data.getPreCertificate()), data
                .getExtensions(), getSingletonList(data.getExtraCertificates())))
        .collect(Collectors.toList()));
    LOG.info(String.format(
        "CDS statistics: X509 Certificates: %10d \t X509 Chains: %10d \t TBS Certificates: %10d",
        X509_CERTIFICATES.size(), X509_CHAINS.size(), TBS_CERTIFICATES.size()));
  }

  /**
   * Returns a reference to the underlying collection.
   */
  public Collection<CertificateData> getDataSet() {
    return dataSet;
  }

  private Object readResolve() {
    CertificateDataSet cds = new CertificateDataSet();
    cds.addAll(getDataSet());
    return cds;
  }
}
