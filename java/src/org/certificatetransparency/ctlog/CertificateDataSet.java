package org.certificatetransparency.ctlog;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

import com.google.common.base.Function;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

/**
 * An internal data structure that keeps sets of certificates and certificates chains
 * retrieved from a CT Log server. To keep memory low all chains and certificates are
 * made into a singleton representation.
 */
public class CertificateDataSet implements Serializable {
  private static final long serialVersionUID = 1L;

  private static final Log LOG = LogFactory.getLog(CertificateDataSet.class);

  public static final ConcurrentMap<X509CertificateObject, X509CertificateObject> X509_CERTIFICATES =
      Maps.newConcurrentMap();

  public static final ConcurrentMap<List<X509CertificateObject>, List<X509CertificateObject>> X509_CHAINS =
      Maps.newConcurrentMap();

  public static final ConcurrentMap<TBSCertificate, TBSCertificate> TBS_CERTIFICATES =
      Maps.newConcurrentMap();

  private Set<CertificateData> dataSet = Sets.newHashSet();

  public static X509CertificateObject getSingletonX509Certificate(X509CertificateObject certificate) {
    return addOrGet(X509_CERTIFICATES, certificate);
  }

  protected TBSCertificate getSingletonTBSCertificate(TBSCertificate certificate) {
    return addOrGet(TBS_CERTIFICATES, certificate);
  }

  public static List<X509CertificateObject> getSingletonList(List<X509CertificateObject> chain) {
    List<X509CertificateObject> newChain = new ArrayList<>(chain.size());

    for (X509CertificateObject cert : chain)
      newChain.add(getSingletonX509Certificate(cert));

    return addOrGet(X509_CHAINS, newChain);
  }

  private static <X> X addOrGet(ConcurrentMap<X, X> certMap, X certificate) {
    if (certificate != null) {
      X old = certMap.putIfAbsent(certificate, certificate);
      return old != null ? old : certificate;
    }

    return null;
  }

  public boolean addAll(Collection<CertificateData> cds) {
    boolean added = Iterables.addAll(dataSet, Iterables.transform(cds, new Function<CertificateData, CertificateData>() {
      @Override public CertificateData apply(CertificateData data) {
        return CertificateData.newData(data.getType(), data.getCertificate(),
            data.getPreCertificate(), data.getExtensions(), data.getExtraCertificates());
      }
    }));

    LOG.info(String.format("CDS statistics: X509 Certificates: %10d \t X509 Chains: %10d \t TBS Certificates: %10d",
        X509_CERTIFICATES.size(), X509_CHAINS.size(), TBS_CERTIFICATES.size()));

    return added;
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
